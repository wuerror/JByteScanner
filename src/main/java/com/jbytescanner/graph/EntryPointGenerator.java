package com.jbytescanner.graph;

import com.jbytescanner.model.ApiRoute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import java.util.*;

public class EntryPointGenerator {
    private static final Logger logger = LoggerFactory.getLogger(EntryPointGenerator.class);
    private static final String DUMMY_MAIN_CLASS = "com.jbytescanner.DummyMain";
    private static final String DUMMY_MAIN_METHOD = "main";

    public void generateDummyMain(List<ApiRoute> routes) {
        logger.info("Generating dummy main method for {} routes...", routes.size());

        // 1. Create Class
        SootClass dummyClass = new SootClass(DUMMY_MAIN_CLASS, Modifier.PUBLIC);
        dummyClass.setSuperclass(Scene.v().getSootClass("java.lang.Object"));
        Scene.v().addClass(dummyClass);

        // 2. Create Method: public static void main(String[] args)
        Type stringType = RefType.v("java.lang.String");
        ArrayType argsType = ArrayType.v(stringType, 1);
        
        SootMethod mainMethod = new SootMethod(DUMMY_MAIN_METHOD, 
                Collections.singletonList(argsType),
                VoidType.v(), Modifier.PUBLIC | Modifier.STATIC);
        
        dummyClass.addMethod(mainMethod);

        // 3. Create Body
        JimpleBody body = Jimple.v().newBody(mainMethod);
        mainMethod.setActiveBody(body);
        
        // Add locals (args)
        Local argsLocal = Jimple.v().newLocal("args", argsType);
        body.getLocals().add(argsLocal);
        body.getUnits().add(Jimple.v().newIdentityStmt(argsLocal, Jimple.v().newParameterRef(argsType, 0)));

        // 4. Call every controller method
        for (ApiRoute route : routes) {
            addCallToMethod(body, route);
        }

        // 5. Return
        body.getUnits().add(Jimple.v().newReturnVoidStmt());
        
        // 6. Set as EntryPoint
        Scene.v().setEntryPoints(Collections.singletonList(mainMethod));
        logger.info("Dummy main created and set as EntryPoint.");
    }

    private void addCallToMethod(JimpleBody body, ApiRoute route) {
        try {
            SootClass controllerClass = Scene.v().getSootClass(route.getClassName());
            // Important: We need to ensure the class is application class so it gets analyzed
            controllerClass.setApplicationClass();
            
            // Note: ApiRoute signature string might differ slightly from Soot's format
            // We need to find the method by signature matching or name/params
            // route.getMethodSig() example: java.lang.String getUser(java.lang.String)
            // This is just a display string, we need to be careful. 
            // Better to look up by subsignature if possible or iterate methods.
            
            SootMethod targetMethod = findMethod(controllerClass, route.getMethodSig());
            if (targetMethod == null) {
                logger.warn("Could not find method for route: {}", route);
                return;
            }

            // If instance method, create instance first
            Local instanceLocal = null;
            if (!targetMethod.isStatic()) {
                instanceLocal = Jimple.v().newLocal("local_" + controllerClass.getShortName(), controllerClass.getType());
                body.getLocals().add(instanceLocal);
                
                body.getUnits().add(Jimple.v().newAssignStmt(instanceLocal, Jimple.v().newNewExpr(controllerClass.getType())));
                
                // Call constructor <init> if possible? 
                // For simplified CHA, strict correctness of object state isn't required, just the call edge.
                // We skip <init> call to simplify, or we can find a no-arg constructor.
                SootMethod init = getNoArgInit(controllerClass);
                if (init != null) {
                     body.getUnits().add(Jimple.v().newInvokeStmt(
                             Jimple.v().newSpecialInvokeExpr(instanceLocal, init.makeRef())));
                }
            }

            // Prepare arguments (mock nulls/defaults)
            List<Value> args = new ArrayList<>();
            for (Type paramType : targetMethod.getParameterTypes()) {
                args.add(getNullOrZero(paramType));
            }

            // Create Invoke Expression
            InvokeExpr invokeExpr;
            if (targetMethod.isStatic()) {
                invokeExpr = Jimple.v().newStaticInvokeExpr(targetMethod.makeRef(), args);
            } else {
                invokeExpr = Jimple.v().newVirtualInvokeExpr(instanceLocal, targetMethod.makeRef(), args);
            }

            // Add Invoke Statement
            body.getUnits().add(Jimple.v().newInvokeStmt(invokeExpr));

        } catch (Exception e) {
            logger.warn("Failed to generate call for {}", route, e);
        }
    }

    private SootMethod findMethod(SootClass sc, String displaySig) {
        // displaySig is like: java.lang.String getUser(java.lang.String)
        // We do a best-effort fuzzy match or parsing.
        // Quick hack: extract method name
        String[] parts = displaySig.split(" ");
        if (parts.length < 2) return null;
        
        // parts[last] is methodname(args)
        String namePart = parts[parts.length-1]; 
        String methodName = namePart.substring(0, namePart.indexOf('('));
        
        // Find method by name. If overloaded, this might pick the wrong one, 
        // but for Phase 3 Proof of Concept, this is acceptable.
        // Ideally we parse the full signature.
        for (SootMethod sm : sc.getMethods()) {
            if (sm.getName().equals(methodName)) {
                return sm;
            }
        }
        return null;
    }

    private SootMethod getNoArgInit(SootClass sc) {
        try {
            return sc.getMethod("void <init>()");
        } catch (RuntimeException e) {
            return null;
        }
    }

    private Value getNullOrZero(Type type) {
        if (type instanceof PrimType) {
            if (type instanceof IntType || type instanceof BooleanType || type instanceof ByteType || type instanceof ShortType || type instanceof CharType)
                return IntConstant.v(0);
            if (type instanceof LongType) return LongConstant.v(0);
            if (type instanceof FloatType) return FloatConstant.v(0);
            if (type instanceof DoubleType) return DoubleConstant.v(0);
        }
        return NullConstant.v();
    }
}
