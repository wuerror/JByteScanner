package com.jbytescanner.analysis;

import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.FlowSet;
import soot.toolkits.scalar.ForwardBranchedFlowAnalysis;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Branched Forward Flow Analysis for Intra-procedural Taint Propagation
 * Supports basic path sensitivity (null checks) and field sensitivity (base object taint).
 */
public class IntraTaintAnalysis extends ForwardBranchedFlowAnalysis<FlowSet<Value>> {
    private final FlowSet<Value> entrySet;
    // Tracks tainted static fields across flow steps (monotone: only grows)
    private final Set<SootField> taintedStaticFields = new HashSet<>();

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

        // Field Taint: tainted arg passed to a setter-like instance method taints the receiver.
        // Restricted to setter-like methods (set*/add*/put*/append*/insert*/with*) and constructors
        // to prevent taint explosion through service-layer pass-through methods.
        if (unit instanceof InvokeStmt) {
            InvokeExpr invokeExpr = ((InvokeStmt) unit).getInvokeExpr();
            if (invokeExpr instanceof InstanceInvokeExpr) {
                SootMethod calledMethod = invokeExpr.getMethod();
                if (isSetterLike(calledMethod)) {
                    Value base = ((InstanceInvokeExpr) invokeExpr).getBase();
                    for (Value arg : invokeExpr.getArgs()) {
                        if (in.contains(arg)) {
                            for (FlowSet<Value> out : fallOut) {
                                out.add(base);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    /**
     * Returns true if the method is setter-like: constructors or methods whose names begin with
     * set/add/put/append/insert/with/push/enqueue/load/init/configure/update/register.
     * These are the patterns where a tainted argument plausibly contaminates the receiver object.
     */
    private static boolean isSetterLike(SootMethod method) {
        if (method.isConstructor()) return true;
        String name = method.getName();
        return name.startsWith("set") || name.startsWith("add")
            || name.startsWith("put") || name.startsWith("append")
            || name.startsWith("insert") || name.startsWith("with")
            || name.startsWith("push") || name.startsWith("enqueue")
            || name.startsWith("load") || name.startsWith("init")
            || name.startsWith("configure") || name.startsWith("update")
            || name.startsWith("register");
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
        
        // 4. Field Read: a = b.f / a = SomeClass.f (Field Sensitivity)
        if (rhs instanceof InstanceFieldRef) {
            if (in.contains(((InstanceFieldRef) rhs).getBase())) {
                isTainted = true;
            }
        } else if (rhs instanceof StaticFieldRef) {
            // Static field read: tainted if the field was previously written with tainted data
            if (taintedStaticFields.contains(((StaticFieldRef) rhs).getField())) {
                isTainted = true;
            }
        } else if (rhs instanceof ArrayRef) {
            if (in.contains(((ArrayRef) rhs).getBase())) {
                isTainted = true;
            }
        }
        // 5. Method Return Propagation
        else if (rhs instanceof InstanceInvokeExpr) {
            InstanceInvokeExpr invoke = (InstanceInvokeExpr) rhs;
            // Receiver tainted -> return tainted (getter/chain calls, e.g. obj.getUrl())
            if (in.contains(invoke.getBase())) {
                isTainted = true;
            }
            // Arg tainted -> return tainted only for setter-like methods (builder pattern,
            // e.g. builder.setX(tainted).build() -> builder tainted -> build() return tainted).
            // General pass-through methods are handled inter-procedurally by scheduling callees.
            if (!isTainted && isSetterLike(invoke.getMethod())) {
                for (Value arg : invoke.getArgs()) {
                    if (in.contains(arg)) {
                        isTainted = true;
                        break;
                    }
                }
            }
        } else if (rhs instanceof InvokeExpr) {
            // Static (and other non-instance) invocations: arg -> return is kept because static
            // transformation functions (String.format, Paths.get, JSON.toJSON, etc.) correctly
            // propagate taint through their arguments.
            InvokeExpr invoke = (InvokeExpr) rhs;
            for (Value arg : invoke.getArgs()) {
                if (in.contains(arg)) {
                    isTainted = true;
                    break;
                }
            }
        }
        
        if (isTainted) {
            out.add(lhs);
            // Field Write Propagation: x.f = tainted -> Taint x (instance field)
            if (lhs instanceof InstanceFieldRef) {
                out.add(((InstanceFieldRef) lhs).getBase());
            } else if (lhs instanceof ArrayRef) {
                out.add(((ArrayRef) lhs).getBase());
            } else if (lhs instanceof StaticFieldRef) {
                // Static field write: SomeClass.field = tainted -> remember for later reads
                taintedStaticFields.add(((StaticFieldRef) lhs).getField());
            }
        } else {
            // Kill taint if overwritten by safe value
            // Only kill if lhs is a Local (FlowSet<Value> stores Locals)
            if (lhs instanceof Local) {
                out.remove(lhs);
            }
            // Note: we do NOT kill tainted static fields on overwrite because a
            // conservative MAY-analysis assumes any path may have tainted the field.
        }
    }
}
