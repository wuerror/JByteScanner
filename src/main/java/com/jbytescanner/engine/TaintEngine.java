package com.jbytescanner.engine;

import com.jbytescanner.analysis.InterproceduralTaintAnalysis;
import com.jbytescanner.analysis.RuleManager;
import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.core.SootManager;
import com.jbytescanner.graph.CallGraphBuilder;
import com.jbytescanner.graph.ReachabilityAnalyzer;
import com.jbytescanner.graph.EntryPointGenerator;
import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import com.jbytescanner.report.SarifReporter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class TaintEngine {
    private static final Logger logger = LoggerFactory.getLogger(TaintEngine.class);
    private final List<String> targetAppJars;
    private final List<String> depAppJars; // Not used in process_dir but used in classpath
    private final List<String> libJars;
    private final File workspaceDir;
    private final ConfigManager configManager;

    public TaintEngine(List<String> targetAppJars, List<String> depAppJars, List<String> libJars, File workspaceDir, ConfigManager configManager) {
        this.targetAppJars = targetAppJars;
        this.depAppJars = depAppJars;
        this.libJars = libJars;
        this.workspaceDir = workspaceDir;
        this.configManager = configManager;
    }

    public void run() {
        logger.info("Starting Taint Engine...");

        // 1. Init Soot with Strict Isolation
        // Only targetAppJars go into process_dir
        // depAppJars and libJars go into classpath
        List<String> combinedLibs = new ArrayList<>(libJars);
        if (depAppJars != null) combinedLibs.addAll(depAppJars);
        
        List<String> scanPackages = configManager.getConfig().getScanConfig().getScanPackages();
        SootManager.initSoot(targetAppJars, combinedLibs, true, scanPackages); 

        // 2. Load Entry Points
        List<ApiRoute> routes = loadEntryPoints();
        if (routes.isEmpty()) return;

        // 3. Generate Dummy Main (Still needed for CallGraph construction)
        EntryPointGenerator entryPointGenerator = new EntryPointGenerator();
        entryPointGenerator.generateDummyMain(routes);

        // 4. Build Call Graph
        CallGraphBuilder cgBuilder = new CallGraphBuilder();
        CallGraph cg = cgBuilder.build();
        
        logger.info("Call Graph built. Edge count: {}", cg.size());

        // 5. Run Taint Analysis
        logger.info("Running Inter-procedural Taint Analysis...");
        RuleManager ruleManager = new RuleManager(configManager.getConfig());
        
        // 5.1 Optimization: Backward Reachability Pruning
        logger.info("Performing Backward Reachability Analysis for pruning...");
        Set<SootMethod> sinks = new HashSet<>();
        Iterator<Edge> edges = cg.iterator();
        while (edges.hasNext()) {
            Edge e = edges.next();
            SootMethod tgt = e.tgt();
            if (tgt != null && ruleManager.isSink(tgt)) {
                sinks.add(tgt);
            }
        }
        logger.info("Identified {} unique sink methods in CallGraph.", sinks.size());
        
        ReachabilityAnalyzer reachabilityAnalyzer = new ReachabilityAnalyzer(cg);
        Set<SootMethod> reachableMethods = reachabilityAnalyzer.computeBackwardReachability(sinks);
        
        // 5.2 Execute Analysis (Phase 7.2: Switched to WorklistEngine)
        logger.info("Initializing WorklistEngine...");
        com.jbytescanner.analysis.WorklistEngine worklistEngine = new com.jbytescanner.analysis.WorklistEngine(cg, ruleManager, reachableMethods);
        
        // Resolve actual SootMethods for entry points
        List<SootMethod> analysisRoots = resolveMethods(routes);
        
        // Run Analysis
        List<Vulnerability> vulnerabilities = worklistEngine.run(analysisRoots);
        
        // Legacy Engine (Commented out for now, can be enabled for verification)
        /*
        InterproceduralTaintAnalysis legacyEngine = new InterproceduralTaintAnalysis(cg, ruleManager, reachableMethods);
        List<Vulnerability> legacyVulns = legacyEngine.run(analysisRoots);
        logger.info("Verification: Worklist found {}, Legacy found {}", vulnerabilities.size(), legacyVulns.size());
        */
        
        // 6. Scoring (Phase 8.2)
        logger.info("Running Vulnerability Scorer (Phase 8.2)...");
        // Ensure AuthConfig is initialized
        com.jbytescanner.config.AuthConfig authConfig = configManager.getConfig().getScanConfig().getAuthConfig();
        if (authConfig == null) {
            authConfig = new com.jbytescanner.config.AuthConfig();
            configManager.getConfig().getScanConfig().setAuthConfig(authConfig);
        }
        com.jbytescanner.score.AuthDetector authDetector = new com.jbytescanner.score.AuthDetector(authConfig);
        com.jbytescanner.score.VulnScorer scorer = new com.jbytescanner.score.VulnScorer(authDetector);
        
        for (Vulnerability vuln : vulnerabilities) {
            // Find corresponding ApiRoute for the sourceMethod
            ApiRoute route = findRoute(routes, vuln.getSourceMethod());
            scorer.score(vuln, route);
        }

        // 7. Generate Report
        if (!vulnerabilities.isEmpty()) {
            SarifReporter reporter = new SarifReporter(workspaceDir);
            reporter.generate(vulnerabilities);
            
            // Phase 8.3: Generate Smart PoCs
            logger.info("Generating Smart PoC payloads...");
            com.jbytescanner.report.PoCReporter pocReporter = new com.jbytescanner.report.PoCReporter(workspaceDir);
            pocReporter.generate(vulnerabilities, routes);
        } else {
            logger.info("No vulnerabilities found. Skipping report generation.");
        }
    }

    private ApiRoute findRoute(List<ApiRoute> routes, String methodSig) {
        if (methodSig == null) return null;
        for (ApiRoute r : routes) {
            // Check if methodSig contains the route's method name/class
            // methodSig is full soot signature e.g. <com.example.Test: void main(java.lang.String[])>
            // route has separate class and method
            if (methodSig.contains(r.getClassName()) && methodSig.contains(r.getMethodSig().replaceAll("\\(.*\\)", ""))) {
                return r;
            }
        }
        return null;
    }



    private List<SootMethod> resolveMethods(List<ApiRoute> routes) {
        List<SootMethod> methods = new ArrayList<>();
        for (ApiRoute route : routes) {
            try {
                SootClass sc = Scene.v().getSootClass(route.getClassName());
                if (!sc.isPhantom()) {
                    // Fuzzy match method name as in EntryPointGenerator
                    String sig = route.getMethodSig();
                    String methodName = sig.split(" ")[sig.split(" ").length - 1].split("\\(")[0];
                    
                    for (SootMethod sm : sc.getMethods()) {
                        if (sm.getName().equals(methodName)) {
                            methods.add(sm);
                            break; 
                        }
                    }
                }
            } catch (Exception e) {
                // ignore
            }
        }
        return methods;
    }

    private List<ApiRoute> loadEntryPoints() {
        File apiFile = new File(workspaceDir, "api.txt");
        List<ApiRoute> routes = new ArrayList<>();
        if (!apiFile.exists()) return routes;

        try {
            List<String> lines = Files.readAllLines(apiFile.toPath());
            for (String line : lines) {
                if (line.startsWith("#") || line.trim().isEmpty()) continue;
                
                String metaJson = null;
                String baseLine = line;
                
                // Check for metadata separator
                if (line.contains(" | {")) {
                    int splitIdx = line.indexOf(" | {");
                    baseLine = line.substring(0, splitIdx);
                    metaJson = line.substring(splitIdx + 3); // "{...}"
                }
                
                String[] parts = baseLine.split(" ", 4);
                if (parts.length >= 4) {
                    ApiRoute route = new ApiRoute(parts[0], parts[1], parts[2], parts[3]);
                    
                    if (metaJson != null) {
                        try {
                            com.google.gson.JsonObject json = com.google.gson.JsonParser.parseString(metaJson).getAsJsonObject();
                            
                            if (json.has("contentType")) {
                                route.setContentType(json.get("contentType").getAsString());
                            }
                            
                            if (json.has("params")) {
                                List<String> params = new ArrayList<>();
                                com.google.gson.JsonArray arr = json.getAsJsonArray("params");
                                arr.forEach(e -> params.add(e.getAsString()));
                                route.setParameters(params);
                            }
                            
                            if (json.has("annotations")) {
                                java.util.Map<String, String> anns = new java.util.HashMap<>();
                                com.google.gson.JsonObject obj = json.getAsJsonObject("annotations");
                                obj.entrySet().forEach(e -> anns.put(e.getKey(), e.getValue().getAsString()));
                                route.setParamAnnotations(anns);
                            }
                        } catch (Exception e) {
                            logger.warn("Failed to parse metadata for route: {}", parts[1]);
                        }
                    }
                    routes.add(route);
                }
            }
        } catch (IOException e) {
            logger.error("Failed to read api.txt", e);
        }
        logger.info("Loaded {} entry points for analysis.", routes.size());
        return routes;
    }
}
