package com.jbytescanner.engine;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DiscoveryEngineFingerprintTest {

    @TempDir
    Path tempDir;

    @Test
    void missingApiIsStale() {
        assertTrue(DiscoveryEngine.isApiCacheStale(tempDir.toFile(), List.of()));
    }

    @Test
    void apiWithoutFingerprintIsStale() throws Exception {
        Files.writeString(tempDir.resolve("api.txt"), "GET /x c m\n", StandardCharsets.UTF_8);
        assertTrue(DiscoveryEngine.isApiCacheStale(tempDir.toFile(), List.of("a.jar")));
    }

    @Test
    void matchingFingerprintIsFresh() throws Exception {
        Path jar = tempDir.resolve("app.jar");
        Files.writeString(jar, "dummy", StandardCharsets.UTF_8);
        String fp = DiscoveryEngine.computeFingerprint(List.of(jar.toString()));
        Files.writeString(tempDir.resolve("api.txt"), "GET /x c m\n", StandardCharsets.UTF_8);
        Files.writeString(tempDir.resolve(DiscoveryEngine.API_FINGERPRINT_FILE), fp, StandardCharsets.UTF_8);
        assertFalse(DiscoveryEngine.isApiCacheStale(tempDir.toFile(), List.of(jar.toString())));
    }

    @Test
    void classpathChangeInvalidatesCache() throws Exception {
        Path jar1 = tempDir.resolve("a.jar");
        Path jar2 = tempDir.resolve("b.jar");
        Files.writeString(jar1, "a", StandardCharsets.UTF_8);
        Files.writeString(jar2, "b", StandardCharsets.UTF_8);
        Files.writeString(tempDir.resolve("api.txt"), "GET /x c m\n", StandardCharsets.UTF_8);
        Files.writeString(tempDir.resolve(DiscoveryEngine.API_FINGERPRINT_FILE),
                DiscoveryEngine.computeFingerprint(List.of(jar1.toString())),
                StandardCharsets.UTF_8);
        assertTrue(DiscoveryEngine.isApiCacheStale(tempDir.toFile(), List.of(jar1.toString(), jar2.toString())));
        assertNotEquals(
                DiscoveryEngine.computeFingerprint(List.of(jar1.toString())),
                DiscoveryEngine.computeFingerprint(List.of(jar2.toString())));
    }
}
