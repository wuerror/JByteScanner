package com.jbytescanner.engine;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AsmRouteExtractorTest {

    @TempDir
    Path tempDir;

    @Test
    void summarizesControllersAndRoutesPerPackage() throws Exception {
        Path root = tempDir.resolve("app-classes");
        writeController(root, "org/srm/demo/SrmController",
                "Lorg/springframework/web/bind/annotation/RestController;",
                "Lorg/springframework/web/bind/annotation/GetMapping;");
        writeController(root, "org/hzero/demo/HzeroController",
                "Lorg/springframework/stereotype/Controller;",
                "Lorg/springframework/web/bind/annotation/RequestMapping;");
        writePlain(root, "org/srm/demo/PlainService");
        writePlain(root, "com/acme/PlainService");

        Map<String, AsmRouteExtractor.PackageEntryStats> stats =
                new AsmRouteExtractor(List.of(), List.of(root.toString()))
                        .summarizeEntryPoints(List.of("org.srm", "org.hzero", "com.acme"));

        AsmRouteExtractor.PackageEntryStats srm = stats.get("org.srm");
        assertTrue(srm.entryScanConfirmed());
        assertEquals(2, srm.classCount());
        assertEquals(1, srm.controllerClasses());
        assertEquals(1, srm.webEntryClasses());
        assertEquals(1, srm.routeCount());
        assertEquals(1, srm.sourceModuleCount());
        assertTrue(srm.sourceModules().contains("app-classes"));

        AsmRouteExtractor.PackageEntryStats hzero = stats.get("org.hzero");
        assertTrue(hzero.entryScanConfirmed());
        assertEquals(1, hzero.classCount());
        assertEquals(1, hzero.controllerClasses());
        assertEquals(1, hzero.routeCount());

        AsmRouteExtractor.PackageEntryStats acme = stats.get("com.acme");
        assertTrue(acme.entryScanConfirmed());
        assertEquals(1, acme.classCount());
        assertEquals(0, acme.controllerClasses());
        assertEquals(0, acme.webEntryClasses());
        assertEquals(0, acme.routeCount());
    }

    @Test
    void marksEntryScanUnconfirmedWhenNoSupportedInputsWereRead() {
        Map<String, AsmRouteExtractor.PackageEntryStats> stats =
                new AsmRouteExtractor(List.of(), List.of(tempDir.resolve("missing").toString()))
                        .summarizeEntryPoints(List.of("org.srm"));

        assertFalse(stats.get("org.srm").entryScanConfirmed());
    }

    private static void writeController(Path root, String internalName,
                                        String classAnnotation, String methodAnnotation)
            throws Exception {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        AnnotationVisitor classAnn = writer.visitAnnotation(classAnnotation, true);
        classAnn.visitEnd();
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "list", "()V", null, null);
        AnnotationVisitor methodAnn = method.visitAnnotation(methodAnnotation, true);
        methodAnn.visitEnd();
        method.visitCode();
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        writeClass(root, internalName, writer.toByteArray());
    }

    private static void writePlain(Path root, String internalName) throws Exception {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        writer.visitEnd();
        writeClass(root, internalName, writer.toByteArray());
    }

    private static void writeClass(Path root, String internalName, byte[] bytes)
            throws Exception {
        Path classFile = root.resolve(internalName + ".class");
        Files.createDirectories(classFile.getParent());
        Files.write(classFile, bytes);
    }
}
