package com.jbytescanner.engine;

import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import pascal.taie.World;
import pascal.taie.WorldBuilder;
import pascal.taie.analysis.pta.PointerAnalysis;
import pascal.taie.analysis.pta.PointerAnalysisResult;
import pascal.taie.analysis.pta.plugin.taint.TaintFlow;
import pascal.taie.config.Options;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.language.classes.JMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

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

        // Publish entry signatures to the PTA plugin BEFORE any Tai-e World is built.
        // JBSScanEntryPointPlugin.onStart() reads this static field when PTA initializes.
        JBSScanEntryPointPlugin.entrySignatures = entrySignatures;

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

        args.add("-pp"); // Prepend JVM classpath (required when embedded as library)
        args.add("-ap"); // Allow phantom classes for incomplete classpaths

        // Direct Tai-e output files to the workspace dir
        args.add("--output-dir");
        args.add(workspaceDir.getAbsolutePath());

        // Enable Pointer Analysis and Taint Analysis Plugin.
        // Use context-insensitive PTA (cs:ci) + only-app:true for scalability.
        // cs:1-obj on 27K+ classes causes exponential state-space explosion (OOM).
        // only-app:true restricts analysis to application classes; taint detection
        // at call sites into library sinks (Runtime.exec, Statement.executeQuery, etc.)
        // still works because those call sites ARE in application code.
        String ptaConfig = "pta=cs:ci;only-app:true;taint-config:" + taintConfigPath;
        args.add("-a");
        args.add(ptaConfig);

        logger.info("Running Tai-e with arguments: {}", String.join(" ", args));

        // Note: Main.main calls System.exit() by default in some Tai-e versions upon completion/error.
        // In library mode, we should ideally use Options.parse and run analyses manually,
        // or ensure Main.main is safe.
        // Let's manually parse and execute to avoid System.exit
        ptaConfig += ";implicit-entries:true";
        // Inject our custom entry-point plugin so web controller methods are added to the call graph.
        // Without this, Spring/JAX-RS controller methods are never in the PTA call graph,
        // causing TaintAnalysis to find zero flows even for genuinely vulnerable code.
        ptaConfig += ";plugins:[com.jbytescanner.engine.JBSScanEntryPointPlugin]";
        args.set(args.size() - 1, ptaConfig);
        String[] argsArray = args.toArray(new String[0]);
        
        try {
            Options options = Options.parse(argsArray);
            pascal.taie.config.LoggerConfigs.setOutput(options.getOutputDir());

            // Build the analysis plan from CLI args (pta + taint config)
            java.io.InputStream content = pascal.taie.config.Configs.getAnalysisConfig();
            java.util.List<pascal.taie.config.AnalysisConfig> analysisConfigs =
                    pascal.taie.config.AnalysisConfig.parseConfigs(content);
            pascal.taie.config.ConfigManager mgr =
                    new pascal.taie.config.ConfigManager(analysisConfigs);
            pascal.taie.config.AnalysisPlanner planner =
                    new pascal.taie.config.AnalysisPlanner(mgr, options.getKeepResult());
            java.util.List<pascal.taie.config.PlanConfig> planConfigs =
                    pascal.taie.config.PlanConfig.readConfigs(options);
            mgr.overwriteOptions(planConfigs);
            pascal.taie.config.Plan plan = planner.expandPlan(planConfigs, false);

            // Build World: use the WorldBuilder class specified in options (defaults to SootWorldBuilder)
            // World.reset() is called inside builder.build(), so no explicit reset is needed.
            Class<? extends WorldBuilder> builderClass = options.getWorldBuilderClass();
            WorldBuilder worldBuilder = builderClass.getDeclaredConstructor().newInstance();
            worldBuilder.build(options, plan.analyses());

            // Execute the analysis plan (runs PTA which internally triggers TaintAnalysis plugin)
            new pascal.taie.analysis.AnalysisManager(plan).execute();
            pascal.taie.config.LoggerConfigs.reconfigure();
        } catch (Exception e) {
            logger.error("Tai-e analysis failed", e);
        }

        logger.info("Tai-e Analysis Finished.");

        // 4. Extract Taint Results
        // Tai-e stores the results in its World/ResultManager.
        // Specifically, TaintAnalysis is a PTA plugin. We can retrieve TaintManager.
        
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // TaintAnalysis is a PTA plugin: its results are stored inside the PTA result, not World directly.
        PointerAnalysisResult ptaResult = World.get().getResult(PointerAnalysis.ID);
        Set<TaintFlow> taintFlows = null;
        if (ptaResult != null) {
            taintFlows = ptaResult.getResult(
                    pascal.taie.analysis.pta.plugin.taint.TaintAnalysis.class.getName());
        }
        if (taintFlows != null) {
            for (TaintFlow flow : taintFlows) {
                Vulnerability vuln = convertFlowToVuln(flow, routes, ruleManager);
                if (vuln != null) {
                    vulnerabilities.add(vuln);
                }
            }
        } else {
            logger.warn("TaintAnalysis result not found. PTA result: {}. Check if 'taint' analysis was configured correctly.",
                    ptaResult != null ? "present" : "absent");
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
        // TaintFlow is a public record, but SourcePoint and SinkPoint are package-private in Tai-e.
        // We must treat the return values as Object and use reflection to access their methods.

        String sourceMethodSig = null;
        try {
            Object sourcePoint = flow.sourcePoint();
            if (sourcePoint != null) {
                JMethod method = (JMethod) sourcePoint.getClass()
                        .getMethod("getContainer").invoke(sourcePoint);
                if (method != null) sourceMethodSig = method.getSignature();
            }
        } catch (Exception e) {
            logger.warn("Failed to extract source point from TaintFlow", e);
        }

        String sinkMethodSig = null;
        try {
            Object sinkPoint = flow.sinkPoint();
            if (sinkPoint != null) {
                // SinkPoint.sinkCall() returns Invoke; MethodRef.toString() == full signature
                Invoke invoke = (Invoke) sinkPoint.getClass()
                        .getMethod("sinkCall").invoke(sinkPoint);
                if (invoke != null) sinkMethodSig = invoke.getMethodRef().toString();
            }
        } catch (Exception e) {
            logger.warn("Failed to extract sink point from TaintFlow", e);
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