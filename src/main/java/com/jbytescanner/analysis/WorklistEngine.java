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

/**
 * Phase 7.2: Worklist-based Taint Analysis Engine.
 * Replaces recursion with an iterative queue to prevent StackOverflow and enable advanced optimizations.
 */
public class WorklistEngine {
    private static final Logger logger = LoggerFactory.getLogger(WorklistEngine.class);
    private final CallGraph cg;
    private final RuleManager ruleManager;
    private final SummaryGenerator summaryGenerator;
    private final Set<AnalysisState> visitedStates = new HashSet<>();
    private final Queue<Task> worklist = new LinkedList<>();
    private final List<Vulnerability> vulnerabilities = new ArrayList<>();
    
    // Cache for summaries (Leaf methods only for now, or methods where we trust the summary)
    private final Map<SootMethod, MethodSummary> summaryCache = new HashMap<>();
    
    // Optional: pruning set
    private final Set<SootMethod> reachableMethods;

    public WorklistEngine(CallGraph cg, RuleManager ruleManager, Set<SootMethod> reachableMethods) {
        this.cg = cg;
        this.ruleManager = ruleManager;
        this.reachableMethods = reachableMethods;
        this.summaryGenerator = new SummaryGenerator(ruleManager);
    }

    /**
     * Represents a unit of work for the engine.
     */
    private static class Task {
        SootMethod method;
        FlowSet<Value> initialTaint;
        List<String> callStack;

        Task(SootMethod method, FlowSet<Value> initialTaint, List<String> callStack) {
            this.method = method;
            this.initialTaint = initialTaint;
            this.callStack = callStack;
        }
    }

    public List<Vulnerability> run(List<SootMethod> entryPoints) {
        logger.info("[Worklist] Starting analysis on {} entry points...", entryPoints.size());
        
        // 1. Initialize Worklist
        for (SootMethod ep : entryPoints) {
            if (!ep.hasActiveBody()) continue;
            
            FlowSet<Value> initialTaint = new ArraySparseSet<>();
            for (Local param : ep.getActiveBody().getParameterLocals()) {
                initialTaint.add(param);
            }
            
            schedule(ep, initialTaint, new ArrayList<>());
        }

        // 2. Process Worklist
        int processedCount = 0;
        int leafSkipCount = 0;

        while (!worklist.isEmpty()) {
            Task task = worklist.poll();
            processedCount++;
            
            analyzeTask(task);

            if (processedCount % 1000 == 0) {
                logger.info("[Worklist] Processed: {} | Queue: {} | Vulns: {}", 
                    processedCount, worklist.size(), vulnerabilities.size());
            }
        }

        logger.info("[Worklist] Finished. Processed: {} tasks. Found {} vulnerabilities.", 
            processedCount, vulnerabilities.size());
        return vulnerabilities;
    }

    private void schedule(SootMethod method, FlowSet<Value> taint, List<String> stack) {
        // Pruning Check
        if (reachableMethods != null && !reachableMethods.contains(method)) {
            return;
        }

        // State Check (Memoization)
        BitSet taintedIndices = new BitSet();
        if (method.hasActiveBody()) {
            List<Local> params = method.getActiveBody().getParameterLocals();
            for (int i = 0; i < params.size(); i++) {
                if (taint.contains(params.get(i))) {
                    taintedIndices.set(i);
                }
            }
        }
        AnalysisState state = new AnalysisState(method, taintedIndices);
        
        if (visitedStates.contains(state)) return;
        visitedStates.add(state);

        // Add to Queue
        worklist.add(new Task(method, taint, stack));
    }

    private void analyzeTask(Task task) {
        SootMethod method = task.method;
        if (!method.hasActiveBody()) return;

        // Call Stack Depth Check
        if (task.callStack.size() > 15) return;
        task.callStack.add(method.getSignature());

        // Run Intra-procedural Analysis
        Body body = method.getActiveBody();
        ExceptionalUnitGraph graph = new ExceptionalUnitGraph(body);
        IntraTaintAnalysis intraAnalysis = new IntraTaintAnalysis(graph, task.initialTaint);

        for (Unit unit : body.getUnits()) {
            FlowSet<Value> flowBefore = intraAnalysis.getFlowBefore(unit);
            Stmt stmt = (Stmt) unit;

            if (stmt.containsInvokeExpr()) {
                InvokeExpr invokeExpr = stmt.getInvokeExpr();
                SootMethod callee = invokeExpr.getMethod();
                
                // 1. Sink Check
                if (ruleManager.isSink(callee)) {
                    checkSink(method, unit, callee, invokeExpr, flowBefore, task.callStack);
                }
                
                // 2. Inter-procedural Propagation
                propagateToCallee(method, stmt, invokeExpr, flowBefore, task.callStack);
            }
        }
    }

    private void propagateToCallee(SootMethod caller, Stmt callSite, InvokeExpr invokeExpr, 
                                   FlowSet<Value> flowBefore, List<String> currentStack) {
        
        // Find potential targets (Polyglot/Soot call graph)
        Iterator<Edge> edges = cg.edgesOutOf(callSite);
        
        while (edges.hasNext()) {
            Edge edge = edges.next();
            SootMethod tgt = edge.tgt();

            if (!tgt.hasActiveBody() || tgt.getDeclaringClass().isJavaLibraryClass()) continue;

            // --- Phase 7.2 Optimization: Leaf Summary Application ---
            // Check if target is a "Leaf" (no outgoing calls to application code)
            // or if we already have a TRUSTED summary.
            // For now, we only trust summaries if the method is strictly a leaf in the CG.
            
            if (isLeaf(tgt)) {
                applyLeafSummary(tgt, invokeExpr, flowBefore, currentStack);
            } else {
                // Not a leaf, must schedule for analysis
                scheduleCallee(tgt, invokeExpr, flowBefore, currentStack);
            }
        }
    }

    private boolean isLeaf(SootMethod method) {
        // A method is a leaf if it makes no calls to application methods.
        // We check edges out of the method.
        Iterator<Edge> edges = cg.edgesOutOf(method);
        while (edges.hasNext()) {
            Edge e = edges.next();
            SootMethod t = e.tgt();
            if (!t.getDeclaringClass().isJavaLibraryClass()) {
                return false; // Calls another app method -> Not a leaf
            }
        }
        return true;
    }

    private void applyLeafSummary(SootMethod method, InvokeExpr invokeExpr, 
                                  FlowSet<Value> flowBefore, List<String> stack) {
        
        // Get or Generate Summary
        MethodSummary summary = summaryCache.computeIfAbsent(method, m -> summaryGenerator.generate(m));
        if (summary == null) return;

        // Check Params -> Return
        // Note: This logic assumes we can update the FLOW in the CURRENT method (caller).
        // But IntraTaintAnalysis is already done.
        // Wait, 'IntraTaintAnalysis' runs ONCE at start of analyzeTask.
        // If we find that a callee returns taint, we ideally need to update the flow *after* this statement
        // and propagate it further in the current method.
        // The current simple approach (just creating tasks) doesn't support "getting return taint back".
        // To support "Return Taint", we would need to either:
        // A) Rerun IntraAnalysis with the new knowledge (expensive)
        // B) Use an IFDS-style solver where facts are propagated.
        
        // Current Limitation of Phase 7.2 (and 7.1):
        // We do NOT yet support Taint Return Propagation (x = tainted(); sink(x)).
        // We primarily support Forward Propagation into Sinks (source -> pass -> sink).
        // The prompt for Phase 6.5 mentioned "Object Taint Propagation" was added.
        // Let's check IntraTaintAnalysis.java line 131: "Method Return Propagation (Object Taint)".
        // It says: "If base object is tainted, assume its method returns are tainted".
        // It does NOT handle "Argument is tainted -> Return is tainted".
        
        // So for now, the Summary Application is MAINLY useful for:
        // "Param -> Sink" detection inside the Leaf Method, avoiding a task schedule.
        
        // 1. Check Params -> Sink (in Leaf)
        Body calleeBody = method.getActiveBody();
        List<Local> params = calleeBody.getParameterLocals();
        
        for (int i = 0; i < invokeExpr.getArgCount(); i++) {
            if (i >= params.size()) break;
            
            Value arg = invokeExpr.getArg(i);
            if (flowBefore.contains(arg)) {
                // Check if this param reaches a sink in the summary
                Set<String> reachedSinks = summary.getReachedSinks(i);
                for (String sinkSig : reachedSinks) {
                    reportVulnerability(method, null, sinkSig, stack); // Unit is inside callee, we don't have it here easily
                }
            }
        }
    }

    private void scheduleCallee(SootMethod callee, InvokeExpr invokeExpr, 
                                FlowSet<Value> flowBefore, List<String> stack) {
        
        FlowSet<Value> calleeTaint = new ArraySparseSet<>();
        Body calleeBody = callee.getActiveBody();
        List<Local> params = calleeBody.getParameterLocals();

        boolean anyTainted = false;
        for (int i = 0; i < invokeExpr.getArgCount(); i++) {
            if (i < params.size()) {
                if (flowBefore.contains(invokeExpr.getArg(i))) {
                    calleeTaint.add(params.get(i));
                    anyTainted = true;
                }
            }
        }

        if (anyTainted) {
            schedule(callee, calleeTaint, new ArrayList<>(stack));
        }
    }

    private void checkSink(SootMethod method, Unit unit, SootMethod callee, 
                          InvokeExpr invokeExpr, FlowSet<Value> flowBefore, List<String> stack) {
        for (Value arg : invokeExpr.getArgs()) {
            if (flowBefore.contains(arg)) {
                reportVulnerability(method, unit, callee.getSignature(), stack);
            }
        }
    }

    private void reportVulnerability(SootMethod sourceMethod, Unit sourceUnit, String sinkSig, List<String> stack) {
        com.jbytescanner.config.SinkRule rule = ruleManager.getSinkRule(sinkSig);
        String vulnType = (rule != null) ? rule.getVulnType() : "Unknown";
        
        List<String> fullTrace = new ArrayList<>(stack);
        fullTrace.add(sinkSig);
        String source = fullTrace.isEmpty() ? "Unknown" : fullTrace.get(0);
        
        Vulnerability vuln = new Vulnerability(vulnType, source, sinkSig, fullTrace);
        
        boolean exists = vulnerabilities.stream().anyMatch(v -> 
            v.getType().equals(vuln.getType()) && 
            v.getSinkMethod().equals(vuln.getSinkMethod()) &&
            v.getSourceMethod().equals(vuln.getSourceMethod())
        );
        
        if (!exists) {
            vulnerabilities.add(vuln);
            logger.warn("[VULN-Worklist] Type: {} | Sink: {} | Source: {}", vulnType, sinkSig, source);
        }
    }
}
