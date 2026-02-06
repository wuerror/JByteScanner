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

import java.util.*;
import java.util.BitSet;

public class InterproceduralTaintAnalysis {
    private static final Logger logger = LoggerFactory.getLogger(InterproceduralTaintAnalysis.class);
    private final CallGraph cg;
    private final RuleManager ruleManager;
    private final SummaryGenerator summaryGenerator;
    private final Map<SootMethod, MethodSummary> summaryCache = new HashMap<>();
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
        this.summaryGenerator = new SummaryGenerator(ruleManager);
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

        // Generate and Cache Summary (Phase 7.1 Integration)
        if (!summaryCache.containsKey(method) && method.hasActiveBody()) {
            MethodSummary summary = summaryGenerator.generate(method);
            if (summary != null) {
                summaryCache.put(method, summary);
                logger.trace("Generated and cached summary for: {}", method.getSignature());
            }
        }

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
        
        // Legacy Engine always assumes full flow because it traces recursively
        Vulnerability vuln = new Vulnerability(vulnType, source, sink.getSignature(), fullTrace, true, rule);
        
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
}
