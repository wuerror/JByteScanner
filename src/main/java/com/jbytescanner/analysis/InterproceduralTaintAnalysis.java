package com.jbytescanner.analysis;

import com.jbytescanner.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.FlowSet;
import soot.toolkits.scalar.ForwardFlowAnalysis;

import java.util.*;

public class InterproceduralTaintAnalysis {
    private static final Logger logger = LoggerFactory.getLogger(InterproceduralTaintAnalysis.class);
    private final CallGraph cg;
    private final RuleManager ruleManager;
    private final Set<String> visitedStates = new HashSet<>(); 
    private final List<Vulnerability> vulnerabilities = new ArrayList<>();

    public InterproceduralTaintAnalysis(CallGraph cg, RuleManager ruleManager) {
        this.cg = cg;
        this.ruleManager = ruleManager;
    }

    public List<Vulnerability> run(List<SootMethod> entryPoints) {
        logger.info("Starting Taint Analysis on {} entry points...", entryPoints.size());
        
        for (SootMethod ep : entryPoints) {
            if (!ep.hasActiveBody()) continue;
            
            FlowSet<Value> initialTaint = new ArraySparseSet<>();
            Body body = ep.getActiveBody();
            for (Local param : body.getParameterLocals()) {
                initialTaint.add(param);
            }
            
            analyzeMethod(ep, initialTaint, new ArrayList<>());
        }
        
        return vulnerabilities;
    }

    private void analyzeMethod(SootMethod method, FlowSet<Value> initialTaint, List<String> callStack) {
        String stateKey = method.getSignature() + initialTaint.toString();
        if (visitedStates.contains(stateKey)) return;
        visitedStates.add(stateKey);
        
        if (callStack.size() > 15) return; 
        
        callStack.add(method.getSignature());
        logger.debug("Analyzing: {} | Tainted: {}", method.getSignature(), initialTaint);

        // Run Intra-procedural Analysis
        Body body = method.getActiveBody();
        ExceptionalUnitGraph graph = new ExceptionalUnitGraph(body);
        IntraTaintAnalysis intraAnalysis = new IntraTaintAnalysis(graph, initialTaint);

        // Check for sinks and recursive calls
        for (Unit unit : body.getUnits()) {
            FlowSet<Value> flowBefore = intraAnalysis.getFlowBefore(unit);
            
            Stmt stmt = (Stmt) unit;
            if (stmt.containsInvokeExpr()) {
                InvokeExpr invokeExpr = stmt.getInvokeExpr();
                SootMethod callee = invokeExpr.getMethod();
                
                // 1. Check Sink
                if (ruleManager.isSink(callee)) {
                    for (Value arg : invokeExpr.getArgs()) {
                        if (flowBefore.contains(arg)) {
                            reportVulnerability(method, unit, callee, callStack);
                        }
                    }
                } else {
                    // Debug Sink matching failure
                    if (callee.getSignature().contains("exec") || callee.getSignature().contains("Runtime")) {
                        logger.debug("Method looks like sink but rule mismatch: {}", callee.getSignature());
                    }
                }
                
                // 2. Inter-procedural Propagation (Follow edges)
                // We map tainted args to callee params
                if (callee.hasActiveBody() && !callee.getDeclaringClass().isJavaLibraryClass()) {
                    FlowSet<Value> calleeTaint = new ArraySparseSet<>();
                    Body calleeBody = callee.getActiveBody();
                    List<Local> params = calleeBody.getParameterLocals();
                    
                    boolean anyArgTainted = false;
                    for (int i = 0; i < invokeExpr.getArgCount(); i++) {
                        if (i < params.size()) {
                            if (flowBefore.contains(invokeExpr.getArg(i))) {
                                calleeTaint.add(params.get(i));
                                anyArgTainted = true;
                            }
                        }
                    }
                    
                    if (anyArgTainted) {
                        analyzeMethod(callee, calleeTaint, new ArrayList<>(callStack));
                    }
                }
                
                // Also check CallGraph edges for polymorphic calls
                Iterator<Edge> edges = cg.edgesOutOf(unit);
                while (edges.hasNext()) {
                    Edge edge = edges.next();
                    SootMethod tgt = edge.tgt();
                    if (tgt != callee && tgt.hasActiveBody() && !tgt.getDeclaringClass().isJavaLibraryClass()) {
                         // Similar mapping logic for dynamic dispatch targets
                         // Omitted for brevity in this iteration
                    }
                }
            }
        }
    }

    private void reportVulnerability(SootMethod method, Unit unit, SootMethod sink, List<String> callStack) {
        com.jbytescanner.config.SinkRule rule = ruleManager.getSinkRule(sink);
        String vulnType = (rule != null) ? rule.getVulnType() : "Unknown";
        
        // Add current location to stack
        List<String> fullTrace = new ArrayList<>(callStack);
        fullTrace.add(sink.getSignature());
        
        // Find source from bottom of stack
        String source = fullTrace.isEmpty() ? "Unknown" : fullTrace.get(0);
        
        Vulnerability vuln = new Vulnerability(vulnType, source, sink.getSignature(), fullTrace);
        
        // Deduplicate
        boolean exists = vulnerabilities.stream().anyMatch(v -> 
            v.getType().equals(vuln.getType()) && 
            v.getSinkMethod().equals(vuln.getSinkMethod()) &&
            v.getSourceMethod().equals(vuln.getSourceMethod())
        );
        
        if (!exists) {
            vulnerabilities.add(vuln);
            logger.warn("[VULN] Type: {} | Sink: {} | Source: {}", vulnType, sink.getSignature(), source);
        }
    }

    /**
     * Simple Forward Flow Analysis for Intra-procedural Taint Propagation
     */
    class IntraTaintAnalysis extends ForwardFlowAnalysis<Unit, FlowSet<Value>> {
        private final FlowSet<Value> entrySet;

        public IntraTaintAnalysis(ExceptionalUnitGraph graph, FlowSet<Value> entrySet) {
            super(graph);
            this.entrySet = entrySet;
            doAnalysis();
        }

        @Override
        protected FlowSet<Value> newInitialFlow() {
            return new ArraySparseSet<>();
        }

        @Override
        protected FlowSet<Value> entryInitialFlow() {
            return entrySet;
        }

        @Override
        protected void merge(FlowSet<Value> in1, FlowSet<Value> in2, FlowSet<Value> out) {
            in1.union(in2, out);
        }

        @Override
        protected void copy(FlowSet<Value> source, FlowSet<Value> dest) {
            source.copy(dest);
        }

        @Override
        protected void flowThrough(FlowSet<Value> in, Unit unit, FlowSet<Value> out) {
            in.copy(out);

            // Taint Propagation Logic
            if (unit instanceof IdentityStmt) {
                // Keep existing taint for parameters (they are pre-seeded in entrySet)
                // Do nothing, just flow through. 
                // If we remove(lhs), we kill the taint we just seeded!
            } else if (unit instanceof DefinitionStmt) {
                DefinitionStmt def = (DefinitionStmt) unit;
                Value lhs = def.getLeftOp();
                Value rhs = def.getRightOp();

                boolean isTainted = false;
                
                // 1. Direct assignment: a = b
                if (in.contains(rhs)) {
                    isTainted = true;
                }
                
                // 2. Binary expr: a = b + c
                if (rhs instanceof BinopExpr) {
                    BinopExpr binop = (BinopExpr) rhs;
                    if (in.contains(binop.getOp1()) || in.contains(binop.getOp2())) {
                        isTainted = true;
                    }
                }
                
                // 3. Cast: a = (String) b
                if (rhs instanceof CastExpr) {
                    if (in.contains(((CastExpr) rhs).getOp())) {
                        isTainted = true;
                    }
                }
                
                // 4. StringBuilder append (simplified)
                // Ideally handled by String/StringBuilder models, but basic flow works for simple cases
                
                if (isTainted) {
                    out.add(lhs);
                } else {
                    // Kill taint if overwritten by safe value (Gen/Kill)
                    // Note: ArraySparseSet remove is by value equality. 
                    // Local variables are unique objects in Soot, so this works.
                    out.remove(lhs);
                }
            }
        }
    }
}
