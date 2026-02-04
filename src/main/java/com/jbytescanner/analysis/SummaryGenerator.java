package com.jbytescanner.analysis;

import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.FlowSet;

import java.util.List;

public class SummaryGenerator {
    private final RuleManager ruleManager;

    public SummaryGenerator(RuleManager ruleManager) {
        this.ruleManager = ruleManager;
    }

    /**
     * Generates a summary for the given method by running intra-procedural analysis
     * for each parameter and 'this'.
     */
    public MethodSummary generate(SootMethod method) {
        if (!method.hasActiveBody()) return null;

        MethodSummary summary = new MethodSummary(method.getSignature());
        Body body = method.getActiveBody();
        List<Local> params = body.getParameterLocals();

        // 1. Analyze "this" flow (if non-static)
        if (!method.isStatic()) {
            try {
                FlowSet<Value> initialTaint = new ArraySparseSet<>();
                initialTaint.add(body.getThisLocal());
                analyzeTaintFlow(body, initialTaint, -1, summary);
            } catch (Exception e) {
                // Ignore if getThisLocal fails (shouldn't happen for non-static)
            }
        }

        // 2. Analyze parameter flows
        for (int i = 0; i < params.size(); i++) {
            FlowSet<Value> initialTaint = new ArraySparseSet<>();
            initialTaint.add(params.get(i));
            analyzeTaintFlow(body, initialTaint, i, summary);
        }

        return summary;
    }

    private void analyzeTaintFlow(Body body, FlowSet<Value> initialTaint, int paramIndex, MethodSummary summary) {
        ExceptionalUnitGraph graph = new ExceptionalUnitGraph(body);
        IntraTaintAnalysis analysis = new IntraTaintAnalysis(graph, initialTaint);

        for (Unit unit : body.getUnits()) {
            FlowSet<Value> flow = analysis.getFlowBefore(unit);
            
            // Check Return
            if (unit instanceof ReturnStmt) {
                Value retOp = ((ReturnStmt) unit).getOp();
                if (flow.contains(retOp)) {
                    if (paramIndex == -1) summary.setThisToReturn(true);
                    else summary.addParamToReturnFlow(paramIndex);
                }
            }

            // Check Sinks
            Stmt stmt = (Stmt) unit;
            if (stmt.containsInvokeExpr()) {
                InvokeExpr invoke = stmt.getInvokeExpr();
                SootMethod callee = invoke.getMethod();
                
                if (ruleManager.isSink(callee)) {
                     for (Value arg : invoke.getArgs()) {
                         if (flow.contains(arg)) {
                             // If paramIndex is -1 (this), we don't track sink reachability from 'this' in summary yet
                             // mainly because we focus on external input sources (args).
                             if (paramIndex != -1) {
                                 summary.addSinkReachability(paramIndex, callee.getSignature());
                             }
                         }
                     }
                }
            }
        }
    }
}
