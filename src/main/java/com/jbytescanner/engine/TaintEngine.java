package com.jbytescanner.engine;

import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.core.SootManager;
import com.jbytescanner.graph.CallGraphBuilder;
import com.jbytescanner.graph.EntryPointGenerator;
import com.jbytescanner.graph.ReachabilityAnalyzer;
import com.jbytescanner.model.ApiRoute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.jimple.toolkits.callgraph.CallGraph;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class TaintEngine {
    private static final Logger logger = LoggerFactory.getLogger(TaintEngine.class);
    private final List<String> appJars;
    private final List<String> libJars;
    private final File workspaceDir;
    private final ConfigManager configManager;

    public TaintEngine(List<String> appJars, List<String> libJars, File workspaceDir, ConfigManager configManager) {
        this.appJars = appJars;
        this.libJars = libJars;
        this.workspaceDir = workspaceDir;
        this.configManager = configManager;
    }

    public void run() {
        logger.info("Starting Taint Engine...");

        // 1. Init Soot in Whole Program Mode
        SootManager.initSoot(appJars, libJars, true); 

        // 2. Load Entry Points from api.txt
        List<ApiRoute> entryPoints = loadEntryPoints();
        if (entryPoints.isEmpty()) {
            logger.warn("No entry points found in api.txt. Skipping analysis.");
            return;
        }

        // 3. Generate Dummy Main
        EntryPointGenerator entryPointGenerator = new EntryPointGenerator();
        entryPointGenerator.generateDummyMain(entryPoints);

        // 4. Build Call Graph
        CallGraphBuilder cgBuilder = new CallGraphBuilder();
        CallGraph cg = cgBuilder.build();
        
        logger.info("Call Graph built. Edge count: {}", cg.size());

        // 5. Basic Reachability Analysis (Phase 3 Demo)
        // Hardcoded check for Runtime.exec to validate java-sec-code RCE detection
        ReachabilityAnalyzer analyzer = new ReachabilityAnalyzer(cg);
        analyzer.findPathToSink("java.lang.Process exec(java.lang.String)");
    }

    private List<ApiRoute> loadEntryPoints() {
        File apiFile = new File(workspaceDir, "api.txt");
        List<ApiRoute> routes = new ArrayList<>();
        if (!apiFile.exists()) return routes;

        try {
            List<String> lines = Files.readAllLines(apiFile.toPath());
            for (String line : lines) {
                if (line.startsWith("#") || line.trim().isEmpty()) continue;
                String[] parts = line.split(" ", 4);
                if (parts.length >= 4) {
                    routes.add(new ApiRoute(parts[0], parts[1], parts[2], parts[3]));
                }
            }
        } catch (IOException e) {
            logger.error("Failed to read api.txt", e);
        }
        logger.info("Loaded {} entry points for analysis.", routes.size());
        return routes;
    }
}
