package com.jbytescanner.engine;

import com.jbytescanner.core.SootManager;
import com.jbytescanner.model.ApiRoute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class DiscoveryEngine {
    private static final Logger logger = LoggerFactory.getLogger(DiscoveryEngine.class);
    private final List<String> jarPaths;
    private final String projectName;

    public DiscoveryEngine(List<String> jarPaths, String projectName) {
        this.jarPaths = jarPaths;
        this.projectName = projectName;
    }

    public void run() {
        logger.info("Starting Discovery Engine for project: {}", projectName);
        
        // 1. Init Soot
        SootManager.initSoot(jarPaths);
        
        // 2. Extract Routes
        RouteExtractor extractor = new RouteExtractor();
        List<ApiRoute> routes = extractor.extract();
        
        logger.info("Found {} API Routes.", routes.size());
        
        // 3. Write Output
        writeApiTxt(routes);
    }

    private void writeApiTxt(List<ApiRoute> routes) {
        List<String> lines = new ArrayList<>();
        
        // Add Header
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        lines.add(String.format("### Project: %s | Scan Session: %s | Jars: %d ###", projectName, timestamp, jarPaths.size()));
        
        lines.addAll(routes.stream()
                .map(ApiRoute::toString)
                .collect(Collectors.toList()));
        
        String filename = "api_" + sanitizeFilename(projectName) + ".txt";
        
        try {
            // Overwrite per project (since filenames are distinct now)
            Files.write(Paths.get(filename), lines);
            logger.info("Routes written to {}", filename);
        } catch (IOException e) {
            logger.error("Failed to write api file", e);
        }
    }
    
    private String sanitizeFilename(String input) {
        return input.replaceAll("[^a-zA-Z0-9.-]", "_");
    }
}
