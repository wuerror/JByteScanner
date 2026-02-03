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
import soot.toolkits.scalar.ForwardBranchedFlowAnalysis;
import soot.toolkits.scalar.ForwardFlowAnalysis;

import java.util.*;
import java.util.BitSet;

public class InterproceduralTaintAnalysis {
    private static final Logger logger = LoggerFactory.getLogger(InterproceduralTaintAnalysis.class);
    private final CallGraph cg;
    private final RuleManager ruleManager;
    private final Set<AnalysisState> visitedStates = new HashSet<>(); 
    private final List<Vulnerability> vulnerabilities = new ArrayList<>();
    private Set<SootMethod> reachableMethods;
    private int prunedCount = 0;

    public InterproceduralTaintAnalysis(CallGraph cg, RuleManager ruleManager) {
        this(cg, ruleManager, null);
    }

    public InterproceduralTaintAnalysis(CallGraph cg, RuleManager ruleManager, Set<SootMethod> reachableMethods) {
        this.cg = cg;
        this.ruleManager = ruleManager;
        this.reachableMethods = reachableMethods;
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
        
        if (reachableMethods != null) {
            logger.info("Analysis finished. Total pruned method calls: {}", prunedCount);
        }
        return vulnerabilities;
    }

    private void analyzeMethod(SootMethod method, FlowSet<Value> initialTaint, List<String> callStack) {
        // Pruning Check
        if (reachableMethods != null && !reachableMethods.contains(method)) {
            prunedCount++;
            return;
        }

        // Calculate tainted parameter indices for efficient state caching
        BitSet taintedIndices = new BitSet();
        if (method.hasActiveBody()) {
            List<Local> params = method.getActiveBody().getParameterLocals();
            for (int i = 0; i < params.size(); i++) {
                if (initialTaint.contains(params.get(i))) {
                    taintedIndices.set(i);
                }
            }
        }

        AnalysisState state = new AnalysisState(method, taintedIndices);

        if (visitedStates.contains(state)) return;
        visitedStates.add(state);
        
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
     * Branched Forward Flow Analysis for Intra-procedural Taint Propagation
     * Supports basic path sensitivity (null checks) and field sensitivity (base object taint).
     */
    class IntraTaintAnalysis extends ForwardBranchedFlowAnalysis<FlowSet<Value>> {
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
        protected void flowThrough(FlowSet<Value> in, Unit unit, List<FlowSet<Value>> fallOut, List<FlowSet<Value>> branchOuts) {
            // Initialize all outputs with input
            for (FlowSet<Value> out : fallOut) in.copy(out);
            for (FlowSet<Value> out : branchOuts) in.copy(out);

            // 1. Taint Propagation (Gen/Kill) for Definitions
            if (unit instanceof IdentityStmt) {
                // Do nothing for IdentityStmt (e.g., r0 := @parameter0).
                // The taint status of parameters is pre-seeded in the entrySet/in-set.
                // We must NOT treat this as a "clean assignment" to avoid killing the taint.
            } else if (unit instanceof DefinitionStmt) {
                // DefinitionStmt usually has no branches, so we only care about fallOut
                for (FlowSet<Value> out : fallOut) {
                    applyDefinition((DefinitionStmt) unit, in, out);
                }
            }

            // 2. Path Sensitivity (Null Checks)
            if (unit instanceof IfStmt) {
                IfStmt ifStmt = (IfStmt) unit;
                Value condition = ifStmt.getCondition();
                
                if (condition instanceof EqExpr || condition instanceof NeExpr) {
                    BinopExpr binop = (BinopExpr) condition;
                    Value op1 = binop.getOp1();
                    Value op2 = binop.getOp2();
                    
                    Value nullCheckTarget = null;
                    if (op1 instanceof NullConstant && op2 instanceof Local) nullCheckTarget = op2;
                    else if (op2 instanceof NullConstant && op1 instanceof Local) nullCheckTarget = op1;
                    
                    if (nullCheckTarget != null) {
                        // case: if (x == null) goto TARGET
                        if (condition instanceof EqExpr) {
                            // Target (branchOuts): x is null -> Kill Taint
                            for (FlowSet<Value> out : branchOuts) out.remove(nullCheckTarget);
                            // Fallthrough: x != null -> Keep Taint
                        } 
                        // case: if (x != null) goto TARGET
                        else if (condition instanceof NeExpr) {
                            // Target (branchOuts): x != null -> Keep Taint
                            // Fallthrough: x == null -> Kill Taint
                            for (FlowSet<Value> out : fallOut) out.remove(nullCheckTarget);
                        }
                    }
                }
            }
        }
        
        private void applyDefinition(DefinitionStmt def, FlowSet<Value> in, FlowSet<Value> out) {
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
            
            // 4. Field Read: a = b.f (Field Sensitivity)
            if (rhs instanceof InstanceFieldRef) {
                if (in.contains(((InstanceFieldRef) rhs).getBase())) {
                    isTainted = true;
                }
            } else if (rhs instanceof ArrayRef) {
                if (in.contains(((ArrayRef) rhs).getBase())) {
                    isTainted = true;
                }
            }
            // 5. Method Return Propagation (Object Taint)
            // If base object is tainted, assume its method returns are tainted (e.g., getters)
            else if (rhs instanceof InstanceInvokeExpr) {
                InstanceInvokeExpr invoke = (InstanceInvokeExpr) rhs;
                if (in.contains(invoke.getBase())) {
                    isTainted = true;
                }
            }
            
            if (isTainted) {
                out.add(lhs);
                // Field Write Propagation: x.f = tainted -> Taint x
                if (lhs instanceof InstanceFieldRef) {
                    out.add(((InstanceFieldRef) lhs).getBase());
                } else if (lhs instanceof ArrayRef) {
                    out.add(((ArrayRef) lhs).getBase());
                }
            } else {
                // Kill taint if overwritten by safe value
                // Only kill if lhs is a Local (FlowSet<Value> stores Locals)
                if (lhs instanceof Local) {
                    out.remove(lhs);
                }
            }
        }
    }
}
