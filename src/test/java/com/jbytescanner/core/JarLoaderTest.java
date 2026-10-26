package com.jbytescanner.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JarLoaderTest {

    @TempDir
    Path tempDir;

    @Test
    void discoversWebInfClassesWhenDeploymentRootIsScanned() throws Exception {
        Path classes = tempDir.resolve("WEB-INF/classes");
        Files.createDirectories(classes.resolve("com/example"));
        Files.write(classes.resolve("com/example/Demo.class"), new byte[] {0});

        JarLoader.LoadedJars loaded = new JarLoader().loadJars(tempDir.toString(), List.of("com.example"));

        assertTrue(loaded.targetAppJars.contains(classes.toAbsolutePath().normalize().toString()));
    }

    @Test
    void discoversClassesWhenWebInfDirectoryIsScannedDirectly() throws Exception {
        Path webInf = tempDir.resolve("WEB-INF");
        Path classes = webInf.resolve("classes");
        Files.createDirectories(classes.resolve("com/example"));
        Files.write(classes.resolve("com/example/Demo.class"), new byte[] {0});

        JarLoader.LoadedJars loaded = new JarLoader().loadJars(webInf.toString(), List.of("com.example"));

        assertTrue(loaded.targetAppJars.contains(classes.toAbsolutePath().normalize().toString()));
    }

    @Test
    void ranksPackageCandidatesStablyAndIgnoresLibraryPrefixes() throws Exception {
        Path classes = tempDir.resolve("app-classes");
        writeClasses(classes, "org/srm", 3);
        writeClasses(classes, "org/hzero", 2);
        writeClasses(classes, "com/acme", 2);
        writeClasses(classes, "org/apache/ignored", 5);

        JarLoader loader = new JarLoader();
        List<JarLoader.PackageCandidate> candidates =
                loader.rankBasePackageCandidates(List.of(classes.toString()), 10);

        assertEquals(List.of("org.srm", "com.acme", "org.hzero"),
                candidates.stream().map(c -> c.packagePrefix).toList());
        assertEquals(3, candidates.get(0).classCount);
        assertEquals("org.srm", loader.inferBasePackage(List.of(classes.toString())));
    }

    private static void writeClasses(Path root, String packagePath, int count) throws Exception {
        Path dir = root.resolve(packagePath);
        Files.createDirectories(dir);
        for (int i = 0; i < count; i++) {
            Files.write(dir.resolve("C" + i + ".class"), new byte[] {0});
        }
    }
}
