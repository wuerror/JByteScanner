package com.jbytescanner.engine;

import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import pascal.taie.Main;
import pascal.taie.World;
import pascal.taie.analysis.pta.core.heap.HeapModel;
import pascal.taie.analysis.pta.core.heap.Obj;
import pascal.taie.analysis.pta.plugin.taint.TaintAnalysis;
import pascal.taie.analysis.pta.plugin.taint.TaintFlow;
import pascal.taie.analysis.pta.plugin.taint.TaintManager;
import pascal.taie.analysis.pta.pts.Pointer;
import pascal.taie.config.Options;
import pascal.taie.ir.proginfo.MethodRef;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.ir.stmt.Stmt;
import pascal.taie.language.classes.JMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class TaintEngine {
    private static final Logger logger = LoggerFactory.getLogger(TaintEngine.class);

    private final List<String> targetAppJars;
    private final List<String> depAppJars;
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
        logger.info("Starting Tai-e based Taint Analysis Engine...");

        // 1. Prepare Entry Points
        File apiFile = new File(workspaceDir, "api.txt");
        if (!apiFile.exists()) {
            logger.error("api.txt not found. Please run discovery mode first.");
            return;
        }
        List<ApiRoute> routes = loadEntryPoints(apiFile);
        if (routes.isEmpty()) {
            logger.warn("No API routes found. Nothing to analyze.");
            return;
        }

        List<String> entrySignatures = new ArrayList<>();
        for (ApiRoute route : routes) {
            String fullSig = String.format("<%s: %s>", route.getClassName(), route.getMethodSig());
            entrySignatures.add(fullSig);
        }

        // 2. Generate Tai-e Taint Config
        RuleManager ruleManager = new RuleManager(configManager.getConfig());
        String taintConfigPath = ruleManager.generateTaieConfig(entrySignatures, workspaceDir);
        if (taintConfigPath == null) {
            logger.error("Failed to generate Tai-e taint configuration.");
            return;
        }

        // 3. Initialize Tai-e for Taint Analysis
        List<String> combinedLibs = new ArrayList<>(libJars);
        if (depAppJars != null) combinedLibs.addAll(depAppJars);

        // We run Tai-e Main directly to execute the analyses
        List<String> args = new ArrayList<>();
        
        if (targetAppJars != null && !targetAppJars.isEmpty()) {
            args.add("--app-class-path");
            args.add(String.join(System.getProperty("path.separator"), targetAppJars));
        }

        if (combinedLibs != null && !combinedLibs.isEmpty()) {
            args.add("--class-path");
            args.add(String.join(System.getProperty("path.separator"), combinedLibs));
        }

        args.add("-pp"); // Include JVM classes for taint flow through JDK

        // Enable Pointer Analysis and Taint Analysis Plugin
        // Use 2-obj context sensitivity for accuracy, though it might be slower.
        // If performance is an issue, fallback to pta=cs:1-obj or pta=cs:ci
        String ptaConfig = "pta=cs:1-obj;taint-config:" + taintConfigPath;
        args.add("-a");
        args.add(ptaConfig);

        logger.info("Running Tai-e with arguments: {}", String.join(" ", args));

        // Note: Main.main calls System.exit() by default in some Tai-e versions upon completion/error.
        // In library mode, we should ideally use Options.parse and run analyses manually,
        // or ensure Main.main is safe.
        // Let's manually parse and execute to avoid System.exit
        String[] argsArray = args.toArray(new String[0]);
        Options.parse(argsArray);
        World.reset();
        World.get().setOptions(Options.get());
        pascal.taie.frontend.Compiler.compile();
        
        // Setup entries manually if Tai-e doesn't pick them from PTA config easily?
        // Tai-e PTA by default analyzes main class or classes with specified analyses.
        // Actually, we must specify entry methods for PTA if it's a library or web app.
        // We can do this via options.
        // Tai-e doesn't natively take a list of entry methods from CLI easily without modifying PTA config.
        // The standard way in Tai-e to set entry points for library analysis is setting the analysis scope
        // or using `EntryPointManager`.
        
        // Instead of deep Tai-e API hacking here, since Tai-e natively supports "all-application-classes" entry points 
        // for libraries, or we can use the `cg` analysis configuration.
        // For simplicity and matching standard Tai-e behavior, let's configure `pta` to analyze application classes.
        // Tai-e's default behavior for PTA when no main class is specified might be to not analyze anything
        // unless configured. Let's add the library mode or implicit entries option.
        
        // Actually, Tai-e options allows setting main class. Since we don't have one, we can tell PTA to use implicit entries.
        // `pta=implicit-entries:true`
        ptaConfig += ";implicit-entries:true";
        Options.get().getAnalyses().clear(); // Reset to re-add with updated config
        // Re-parse or just update Options manually:
        // Well, we can just execute the analysis manager.
        
        // For now, let's just use Tai-e's standard execution:
        pascal.taie.Main.main(new String[]{
            "--app-class-path", String.join(System.getProperty("path.separator"), targetAppJars != null ? targetAppJars : new ArrayList<>()),
            "--class-path", String.join(System.getProperty("path.separator"), combinedLibs),
            "-pp",
            "-a", ptaConfig
        });

        logger.info("Tai-e Analysis Finished.");

        // 4. Extract Taint Results
        // Tai-e stores the results in its World/ResultManager.
        // Specifically, TaintAnalysis is a PTA plugin. We can retrieve TaintManager.
        
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Since we ran Main.main, World is populated.
        TaintAnalysis taintAnalysis = (TaintAnalysis) World.get().getResult("taint");
        if (taintAnalysis != null) {
            TaintManager taintManager = taintAnalysis.getTaintManager();
            for (TaintFlow flow : taintManager.getTaintFlows()) {
                Vulnerability vuln = convertFlowToVuln(flow, routes, ruleManager);
                if (vuln != null) {
                    vulnerabilities.add(vuln);
                }
            }
        } else {
            logger.warn("TaintAnalysis result not found in Tai-e World. Check if 'taint' analysis was configured correctly.");
        }

        logger.info("Found {} potential vulnerabilities.", vulnerabilities.size());

        // 5. Scoring (Phase 8.2)
        logger.info("Running Vulnerability Scorer...");
        com.jbytescanner.config.AuthConfig authConfig = configManager.getConfig().getScanConfig().getAuthConfig();
        if (authConfig == null) {
            authConfig = new com.jbytescanner.config.AuthConfig();
            configManager.getConfig().getScanConfig().setAuthConfig(authConfig);
        }
        com.jbytescanner.score.AuthDetector authDetector = new com.jbytescanner.score.AuthDetector(authConfig);
        com.jbytescanner.score.VulnScorer scorer = new com.jbytescanner.score.VulnScorer(authDetector);
        
        for (Vulnerability vuln : vulnerabilities) {
            ApiRoute route = findRoute(routes, vuln.getSourceMethod());
            scorer.score(vuln, route);
        }

        // 6. Generate Report
        if (!vulnerabilities.isEmpty()) {
            com.jbytescanner.report.SarifReporter reporter = new com.jbytescanner.report.SarifReporter(workspaceDir);
            reporter.generate(vulnerabilities);
            
            logger.info("Generating Smart PoC payloads...");
            com.jbytescanner.report.PoCReporter pocReporter = new com.jbytescanner.report.PoCReporter(workspaceDir);
            pocReporter.generate(vulnerabilities, routes);
        } else {
            logger.info("No vulnerabilities found. Skipping report generation.");
        }
    }

    private Vulnerability convertFlowToVuln(TaintFlow flow, List<ApiRoute> routes, RuleManager ruleManager) {
        // TaintFlow gives us SourcePoint and SinkPoint
        // For JByteScanner, we need the source method (API route) and sink method.
        
        String sourceMethodSig = null;
        if (flow.getSource().getStmt() != null) {
            // Source is a statement (e.g. call source)
            JMethod method = flow.getSource().getStmt().getMethod();
            if (method != null) {
                sourceMethodSig = method.getSignature();
            }
        } else if (flow.getSource().getMethod() != null) {
            // Source is a parameter source
            sourceMethodSig = flow.getSource().getMethod().getSignature();
        }

        String sinkMethodSig = null;
        Stmt sinkStmt = flow.getSink().getStmt();
        if (sinkStmt instanceof Invoke) {
            MethodRef methodRef = ((Invoke) sinkStmt).getMethodRef();
            sinkMethodSig = methodRef.getSignature();
        } else if (sinkStmt != null && sinkStmt.getMethod() != null) {
             // Fallback
             sinkMethodSig = sinkStmt.getMethod().getSignature();
        }
        
        if (sourceMethodSig == null || sinkMethodSig == null) {
            return null;
        }

        // Find the SinkRule to get the category/severity
        SinkRule sinkRule = ruleManager.getRuleForSink(sinkMethodSig);
        String vulnType = sinkRule != null ? sinkRule.getVulnType() : "Unknown";

        // Build trace
        List<String> trace = new ArrayList<>();
        // Note: Tai-e TaintFlow doesn't easily expose the full path by default in its API 
        // without enabling TaintFlowGraph and running path queries.
        // For MVP, we provide source and sink.
        trace.add(sourceMethodSig + " (Source)");
        trace.add(sinkMethodSig + " (Sink)");

        return new Vulnerability(vulnType, sourceMethodSig, sinkMethodSig, trace, true, sinkRule);
    }

    private ApiRoute findRoute(List<ApiRoute> routes, String methodSig) {
        if (methodSig == null) return null;
        for (ApiRoute r : routes) {
            if (methodSig.contains(r.getClassName()) && methodSig.contains(r.getMethodSig().replaceAll("\\(.*\\)", ""))) {
                return r;
            }
        }
        return null;
    }

    private List<ApiRoute> loadEntryPoints(File apiFile) {
        List<ApiRoute> routes = new ArrayList<>();
        try {
            List<String> lines = Files.readAllLines(apiFile.toPath());
            for (String line : lines) {
                if (line.startsWith("#") || line.trim().isEmpty()) continue;
                
                String metaJson = null;
                String baseLine = line;
                
                if (line.contains(" | {")) {
                    int splitIdx = line.indexOf(" | {");
                    baseLine = line.substring(0, splitIdx);
                    metaJson = line.substring(splitIdx + 3); 
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
        return routes;
    }
}