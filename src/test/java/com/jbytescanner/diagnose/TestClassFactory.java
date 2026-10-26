package com.jbytescanner.diagnose;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.nio.file.Files;
import java.nio.file.Path;

final class TestClassFactory {

    private TestClassFactory() {
    }

    static byte[] callerClass() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "com/example/Caller",
                null, "java/lang/Object", null);
        constructor(writer);
        fileConstructorCall(writer, "a", "(Ljava/lang/String;)V", 1);
        fileConstructorCall(writer, "b", "(Ljava/lang/String;Ljava/lang/String;)V", 2);
        fileConstructorCall(writer, "c", "(Ljava/lang/String;)V", 1);
        writer.visitEnd();
        return writer.toByteArray();
    }

    static Path writeCaller(Path root) throws Exception {
        Path classFile = root.resolve("com/example/Caller.class");
        Files.createDirectories(classFile.getParent());
        Files.write(classFile, callerClass());
        return classFile;
    }

    private static void constructor(ClassWriter writer) {
        MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V",
                null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void fileConstructorCall(ClassWriter writer, String name,
                                            String descriptor, int stringParams) {
        MethodVisitor mv = writer.visitMethod(Opcodes.ACC_PUBLIC, name, descriptor,
                null, null);
        mv.visitCode();
        mv.visitTypeInsn(Opcodes.NEW, "java/io/File");
        mv.visitInsn(Opcodes.DUP);
        for (int i = 0; i < stringParams; i++) {
            mv.visitVarInsn(Opcodes.ALOAD, i + 1);
        }
        String constructorDescriptor = stringParams == 1
                ? "(Ljava/lang/String;)V" : "(Ljava/lang/String;Ljava/lang/String;)V";
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/io/File", "<init>",
                constructorDescriptor, false);
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }
}
