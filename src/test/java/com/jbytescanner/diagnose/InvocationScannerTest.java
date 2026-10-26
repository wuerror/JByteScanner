package com.jbytescanner.diagnose;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InvocationScannerTest {

    @TempDir
    Path tempDir;

    @Test
    void matchesExactOverloadInDirectoryAndReportsCaller() throws Exception {
        Path classes = tempDir.resolve("classes");
        TestClassFactory.writeCaller(classes);

        TaiEMethodSignature target = TaiEMethodSignature.parse(
                "<java.io.File: void <init>(java.lang.String)>");
        InvocationScanner.ScanResult result = InvocationScanner.scan(
                List.of(new InvocationScanner.ArtifactPath(classes.toString(), "TARGET_APP")),
                target, 200);

        assertEquals(2, result.totalMatches());
        assertEquals(2, result.matches().size());
        assertEquals(1, result.artifactsScanned());
        assertTrue(result.matches().stream().anyMatch(match ->
                match.callerSignature().contains(" void a(java.lang.String)>")));
        assertTrue(result.matches().stream().anyMatch(match ->
                match.callerSignature().contains(" void c(java.lang.String)>")));
        assertTrue(result.matches().stream().noneMatch(match ->
                match.callerSignature().contains(" void b(")));
        assertTrue(result.complete());
    }

    @Test
    void doesNotConfuseTheTwoArgumentOverload() throws Exception {
        Path classes = tempDir.resolve("classes2");
        TestClassFactory.writeCaller(classes);

        InvocationScanner.ScanResult result = InvocationScanner.scan(
                List.of(new InvocationScanner.ArtifactPath(classes.toString(), "TARGET_APP")),
                TaiEMethodSignature.parse(
                        "<java.io.File: void <init>(java.lang.String,java.lang.String)>"),
                200);

        assertEquals(1, result.totalMatches());
        assertTrue(result.matches().get(0).callerSignature().contains("void b("));
    }

    @Test
    void scansJarsAndRecordsArtifactRole() throws Exception {
        Path source = tempDir.resolve("classes3");
        Path classFile = TestClassFactory.writeCaller(source);
        Path jar = tempDir.resolve("app.jar");
        try (JarOutputStream out = new JarOutputStream(java.nio.file.Files.newOutputStream(jar))) {
            out.putNextEntry(new JarEntry("com/example/Caller.class"));
            out.write(java.nio.file.Files.readAllBytes(classFile));
            out.closeEntry();
        }

        InvocationScanner.ScanResult result = InvocationScanner.scan(
                List.of(new InvocationScanner.ArtifactPath(jar.toString(), "TARGET_APP")),
                TaiEMethodSignature.parse("<java.io.File: void <init>(java.lang.String)>"),
                200);

        assertEquals(2, result.totalMatches());
        assertEquals("TARGET_APP", result.matches().get(0).artifactRole());
        assertTrue(result.matches().get(0).artifactPath().endsWith("app.jar"));
    }

    @Test
    void missingInvokeIsNoNotYes() throws Exception {
        Path classes = tempDir.resolve("classes4");
        TestClassFactory.writeCaller(classes);

        InvocationScanner.ScanResult result = InvocationScanner.scan(
                List.of(new InvocationScanner.ArtifactPath(classes.toString(), "TARGET_APP")),
                TaiEMethodSignature.parse(
                        "<java.io.File: void <init>(java.net.URI)>"),
                200);

        assertEquals(0, result.totalMatches());
        assertTrue(result.complete());
    }
}
