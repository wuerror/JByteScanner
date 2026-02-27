package com.jbytescanner.engine;

import com.jbytescanner.model.ApiRoute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class DiscoveryEngine {
    private static final Logger logger = LoggerFactory.getLogger(DiscoveryEngine.class);
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
