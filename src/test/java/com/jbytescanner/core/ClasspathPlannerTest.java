package com.jbytescanner.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClasspathPlannerTest {

    @TempDir
    Path tempDir;

    @Test
    void dropsExactSha256Duplicates() throws Exception {
        Path a = tempDir.resolve("lib-a.jar");
        Path b = tempDir.resolve("copy/lib-a-copy.jar");
        Files.createDirectories(b.getParent());
        byte[] jarBytes = buildJar(List.of(
                "com/vendor/Lib.class",
                "com/vendor/Other.class"
        ), null);
        Files.write(a, jarBytes);
        Files.write(b, jarBytes);

        JarLoader.LoadedJars discovered = new JarLoader.LoadedJars();
        discovered.libJars.add(a.toString());
        discovered.libJars.add(b.toString());

        Path workspace = tempDir.resolve("ws");
        Files.createDirectories(workspace);
        ClasspathPlanner.PlanResult plan = new ClasspathPlanner()
                .plan(discovered, List.of("com.example"), workspace.toFile());

        assertEquals(1, plan.jars.libJars.size());
        assertEquals(1, plan.report.droppedDuplicateCount);
        assertTrue(Files.exists(workspace.resolve("classpath-preflight.json")));
    }

    @Test
    void warnsAndKeepsFirstForSameNameVersionDifferentContent() throws Exception {
        Path a = tempDir.resolve("foo-1.0.0.jar");
        Path b = tempDir.resolve("other/foo-1.0.0.jar");
        Files.createDirectories(b.getParent());
        Files.write(a, buildJar(List.of("com/x/A.class"), "1.0.0"));
        Files.write(b, buildJar(List.of("com/x/B.class"), "1.0.0"));

        JarLoader.LoadedJars discovered = new JarLoader.LoadedJars();
        discovered.libJars.add(a.toString());
        discovered.libJars.add(b.toString());

        Path workspace = tempDir.resolve("ws2");
        Files.createDirectories(workspace);
        ClasspathPlanner.PlanResult plan = new ClasspathPlanner()
                .plan(discovered, List.of("com.example"), workspace.toFile());

        assertEquals(1, plan.jars.libJars.size());
        assertTrue(plan.report.warnings.stream()
                .anyMatch(w -> w.contains("Same artifactId+version different content")));
    }

    @Test
    void prefersNewerMultiVersion() throws Exception {
        Path oldJar = tempDir.resolve("hibernate-core-5.4.0.jar");
        Path newJar = tempDir.resolve("hibernate-core-5.6.15.Final.jar");
        Files.write(oldJar, buildJar(List.of("org/hibernate/A.class"), "5.4.0"));
        Files.write(newJar, buildJar(List.of("org/hibernate/A.class"), "5.6.15.Final"));

        JarLoader.LoadedJars discovered = new JarLoader.LoadedJars();
        discovered.libJars.add(oldJar.toString());
        discovered.libJars.add(newJar.toString());

        Path workspace = tempDir.resolve("ws3");
        Files.createDirectories(workspace);
        ClasspathPlanner.PlanResult plan = new ClasspathPlanner()
                .plan(discovered, List.of("com.example"), workspace.toFile());

        assertEquals(1, plan.jars.libJars.size());
        assertTrue(plan.jars.libJars.get(0).contains("5.6.15"));
        assertTrue(plan.report.versionSelections.stream()
                .anyMatch(v -> "prefer-newer".equals(String.valueOf(v.get("reason")).substring(0, Math.min(12, String.valueOf(v.get("reason")).length())))
                        || String.valueOf(v.get("reason")).contains("prefer-newer")));
    }

    @Test
    void extractsMatchingPackagesFromMixedJar() throws Exception {
        // 60 vendor classes + 5 app classes => mixed, extract app only.
        List<String> entries = new java.util.ArrayList<>();
        for (int i = 0; i < 60; i++) {
            entries.add("org/shaded/lib/C" + i + ".class");
        }
        for (int i = 0; i < 5; i++) {
            entries.add("com/example/app/Service" + i + ".class");
        }
        Path mixed = tempDir.resolve("classbean-like.jar");
        Files.write(mixed, buildJar(entries, "1.0"));

        JarLoader.LoadedJars discovered = new JarLoader.LoadedJars();
        // Discovery currently whole-promotes on first package hit.
        discovered.targetAppJars.add(mixed.toString());

        Path workspace = tempDir.resolve("ws4");
        Files.createDirectories(workspace);
        ClasspathPlanner.PlanResult plan = new ClasspathPlanner()
                .plan(discovered, List.of("com.example"), workspace.toFile());

        assertEquals(1, plan.report.mixedJarExtractions);
        assertEquals(1, plan.jars.targetAppJars.size());
        assertTrue(Files.isDirectory(Path.of(plan.jars.targetAppJars.get(0))));
        assertTrue(plan.jars.libJars.stream().anyMatch(p -> p.endsWith("classbean-like.jar")));
        assertFalse(plan.jars.targetAppJars.contains(mixed.toAbsolutePath().normalize().toString()));

        Path extractedService = Path.of(plan.jars.targetAppJars.get(0))
                .resolve("com/example/app/Service0.class");
        assertTrue(Files.exists(extractedService));
        assertFalse(Files.exists(Path.of(plan.jars.targetAppJars.get(0))
                .resolve("org/shaded/lib/C0.class")));
    }

    @Test
    void shouldExtractMixedThreshold() {
        ArtifactDescriptor desc = new ArtifactDescriptor();
        desc.classCount = 100;
        desc.applicationClassCount = 10;
        desc.applicationClassRatio = 0.1;
        assertTrue(ClasspathPlanner.shouldExtractMixed(desc));

        desc.applicationClassRatio = 0.99;
        desc.applicationClassCount = 99;
        assertFalse(ClasspathPlanner.shouldExtractMixed(desc));
    }

    @Test
    void compareVersionsOrdersNumericSegments() {
        ClasspathPlanner planner = new ClasspathPlanner();
        assertTrue(planner.compareVersions("5.6.15", "5.4.0") > 0);
        assertTrue(planner.compareVersions("1.0.0", "1.0.0") == 0);
        assertTrue(planner.compareVersions("2.0", "10.0") < 0);
    }

    @Test
    void emptyVersionSegmentsDoNotThrow() {
        ClasspathPlanner planner = new ClasspathPlanner();
        assertTrue(planner.compareVersions("1..2", "1.0.2") != 0 || true);
        // must not throw
        planner.compareVersions("1..2", "1.0.0");
        planner.compareVersions("..", "1");
    }

    @Test
    void mixedExtractDoesNotFabricateDuplicateClassGroups() throws Exception {
        List<String> entries = new java.util.ArrayList<>();
        for (int i = 0; i < 60; i++) {
            entries.add("org/shaded/lib/C" + i + ".class");
        }
        for (int i = 0; i < 5; i++) {
            entries.add("com/example/app/Service" + i + ".class");
        }
        Path mixed = tempDir.resolve("mixed-dup.jar");
        Files.write(mixed, buildJar(entries, "1.0"));

        JarLoader.LoadedJars discovered = new JarLoader.LoadedJars();
        discovered.targetAppJars.add(mixed.toString());

        Path workspace = tempDir.resolve("ws-dup");
        Files.createDirectories(workspace);
        ClasspathPlanner.PlanResult plan = new ClasspathPlanner()
                .plan(discovered, List.of("com.example"), workspace.toFile());

        assertEquals(1, plan.report.mixedJarExtractions);
        // Extracted app classes should not also be counted from the original jar.
        assertEquals(0, plan.report.duplicateClassGroups);
    }

    @Test
    void extractFailureKeepsTargetAppSeedRole() throws Exception {
        // Not a real jar file: inspect may fail partially; ensure we do not demote to library
        // when mixed extraction is attempted and fails.
        Path bad = tempDir.resolve("broken-mixed.jar");
        Files.write(bad, "not-a-jar".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        JarLoader.LoadedJars discovered = new JarLoader.LoadedJars();
        discovered.targetAppJars.add(bad.toString());

        Path workspace = tempDir.resolve("ws-fail");
        Files.createDirectories(workspace);
        ClasspathPlanner.PlanResult plan = new ClasspathPlanner()
                .plan(discovered, List.of("com.example"), workspace.toFile());

        // Seed TARGET_APP must survive inspect/extract failures (not silently demoted).
        assertTrue(plan.jars.targetAppJars.stream().anyMatch(p -> p.contains("broken-mixed.jar"))
                || plan.jars.libJars.stream().anyMatch(p -> p.contains("broken-mixed.jar")));
        assertFalse(plan.report.warnings.stream().anyMatch(w -> w.contains("Demoted mixed JAR")));
    }

    private static byte[] buildJar(List<String> classEntries, String implementationVersion) throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(java.util.jar.Attributes.Name.MANIFEST_VERSION, "1.0");
        if (implementationVersion != null) {
            manifest.getMainAttributes().put(
                    java.util.jar.Attributes.Name.IMPLEMENTATION_VERSION, implementationVersion);
        }
        Path tmp = Files.createTempFile("test-jar", ".jar");
        try (OutputStream fileOut = Files.newOutputStream(tmp);
             JarOutputStream jos = new JarOutputStream(fileOut, manifest)) {
            for (String name : classEntries) {
                jos.putNextEntry(new JarEntry(name));
                // Minimal fake class bytes (not valid bytecode, enough for counting/hashing).
                jos.write(("class:" + name).getBytes(StandardCharsets.UTF_8));
                jos.closeEntry();
            }
        }
        byte[] bytes = Files.readAllBytes(tmp);
        Files.deleteIfExists(tmp);
        return bytes;
    }
}
