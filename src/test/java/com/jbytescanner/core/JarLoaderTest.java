package com.jbytescanner.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

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
}
