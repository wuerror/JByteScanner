package com.jbytescanner.analysis;

import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.FlowSet;
import soot.toolkits.scalar.ForwardBranchedFlowAnalysis;

import java.util.List;

/**
 * Branched Forward Flow Analysis for Intra-procedural Taint Propagation
 * Supports basic path sensitivity (null checks) and field sensitivity (base object taint).
 */
public class IntraTaintAnalysis extends ForwardBranchedFlowAnalysis<FlowSet<Value>> {
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
