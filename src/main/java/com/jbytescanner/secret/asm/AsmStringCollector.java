package com.jbytescanner.secret.asm;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AsmStringCollector extends ClassVisitor {
    // Map<MethodSignature, List<StringConstant>>
    // MethodSignature format: com.example.Class.methodName(descriptor)
    private final Map<String, List<String>> collectedStrings = new HashMap<>();
    private String currentClassName;

    public AsmStringCollector() {
        super(Opcodes.ASM9);
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        this.currentClassName = name.replace('/', '.');
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        // Soot Style Signature approximation: <com.example.Class: retType methodName(args)>
        // But for unique ID, "com.example.Class.methodName" is usually enough for mapping, 
        // though overloads exist.
        // Let's store ClassName and MethodName separately to easily find in Soot.
        String methodId = currentClassName + "#" + name; // Simple ID
        
        return new MethodVisitor(Opcodes.ASM9) {
            @Override
            public void visitLdcInsn(Object value) {
                if (value instanceof String) {
                    synchronized (collectedStrings) {
                        collectedStrings.computeIfAbsent(methodId, k -> new ArrayList<>()).add((String) value);
                    }
                }
            }
        };
    }

    public Map<String, List<String>> getCollectedStrings() {
        return collectedStrings;
    }
}
