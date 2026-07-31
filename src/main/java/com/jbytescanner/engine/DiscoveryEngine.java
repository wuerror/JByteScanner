package com.jbytescanner.engine;

import com.jbytescanner.model.ApiRoute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Collectors;

public class DiscoveryEngine {
    private static final Logger logger = LoggerFactory.getLogger(DiscoveryEngine.class);

    /** Workspace marker: invalidates cached api.txt when app classpath set changes. */
    public static final String API_FINGERPRINT_FILE = "api-discovery.fingerprint";

    private final List<String> targetAppJars;
    private final List<String> depAppJars;
    private final List<String> libJars;
    private final File workspaceDir;
    private final List<String> filterAnnotations;

    public DiscoveryEngine(List<String> targetAppJars, List<String> depAppJars, List<String> libJars, File workspaceDir, List<String> filterAnnotations) {
        this.targetAppJars = targetAppJars;
        this.depAppJars = depAppJars;
        this.libJars = libJars;
        this.workspaceDir = workspaceDir;
        this.filterAnnotations = filterAnnotations;
    }

    public void run() {
        logger.info("Starting Discovery Engine (ASM mode)...");

        // Use ASM-based extractor: reads class metadata directly from bytecode without
        // building a Tai-e World, making discovery orders of magnitude faster.
        // Only scan targetAppJars — web framework annotations live in business code, not libs.
        List<String> scanJars = new ArrayList<>();
        if (targetAppJars != null) scanJars.addAll(targetAppJars);

        AsmRouteExtractor extractor = new AsmRouteExtractor(filterAnnotations, scanJars);
        List<ApiRoute> routes = extractor.extract();

        logger.info("Found {} API Routes.", routes.size());

        writeApiTxt(routes);
        writeFingerprint(scanJars);
    }

    /**
     * True when the classpath set differs from the discovery that produced
     * the cached {@code api.txt}.  This is informational: api.txt is treated
     * as a human-curated source whitelist and will NOT be auto-overwritten.
     * A stale fingerprint only produces a warning; use {@code -m api} to
     * regenerate.
     */
    public static boolean isApiCacheStale(File workspaceDir, List<String> targetAppJars) {
        File apiFile = new File(workspaceDir, "api.txt");
        if (!apiFile.isFile()) {
            return true;
        }
        File fpFile = new File(workspaceDir, API_FINGERPRINT_FILE);
        if (!fpFile.isFile()) {
            logger.info("api.txt has no {}; classpath may differ from discovery",
                    API_FINGERPRINT_FILE);
            return true;
        }
        try {
            String expected = computeFingerprint(targetAppJars);
            String actual = Files.readString(fpFile.toPath(), StandardCharsets.UTF_8).trim();
            if (!expected.equals(actual)) {
                logger.info("api.txt fingerprint mismatch (classpath may have changed)");
                return true;
            }
            return false;
        } catch (Exception e) {
            logger.warn("Failed to validate api fingerprint: {}", e.toString());
            return true;
        }
    }

    static String computeFingerprint(List<String> targetAppJars) {
        List<String> lines = new ArrayList<>();
        if (targetAppJars != null) {
            for (String path : targetAppJars) {
                if (path == null || path.isBlank()) {
                    continue;
                }
                File f = new File(path);
                String abs = f.getAbsolutePath().replace('\\', '/');
                long size = f.exists() ? f.length() : -1L;
                long mtime = f.exists() ? f.lastModified() : -1L;
                lines.add(abs + "|" + size + "|" + mtime);
            }
        }
        lines.sort(Comparator.naturalOrder());
        String payload = String.join("\n", lines);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(dig) + "\n# jars=" + lines.size();
        } catch (Exception e) {
            return Integer.toHexString(payload.hashCode()) + "\n# jars=" + lines.size();
        }
    }

    private void writeFingerprint(List<String> scanJars) {
        try {
            File fpFile = new File(workspaceDir, API_FINGERPRINT_FILE);
            Files.writeString(fpFile.toPath(), computeFingerprint(scanJars), StandardCharsets.UTF_8);
            logger.info("Wrote API discovery fingerprint: {}", fpFile.getAbsolutePath());
        } catch (IOException e) {
            logger.warn("Failed to write API fingerprint: {}", e.toString());
        }
    }

    private void writeApiTxt(List<ApiRoute> routes) {
        File apiFile = new File(workspaceDir, "api.txt");
        List<String> lines = routes.stream()
                .map(ApiRoute::toString)
                .collect(Collectors.toList());

        try {
            Files.write(apiFile.toPath(), lines);
            logger.info("API Dictionary written to: {}", apiFile.getAbsolutePath());
        } catch (IOException e) {
            logger.error("Failed to write api file", e);
        }
    }
}
