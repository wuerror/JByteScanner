package com.jbytescanner.engine;

import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import pascal.taie.config.Options;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TaintEngine {
    private static final Logger logger = LoggerFactory.getLogger(TaintEngine.class);

    // Matches: TaintFlow{<sourceMethod>/paramIdx -> <container>[stmtIdx@Lline] invokeText/argIdx}
    private static final Pattern TAINT_FLOW_PATTERN = Pattern.compile(
            "TaintFlow\\{<([^>]+)>/(\\d+) -> <([^>]+)>\\[\\d+@L\\d+\\] (.*?)/(\\d+)\\}");

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
        // Pass all app JARs (target + dep) so RuleManager can ASM-pre-scan bytecode
        // and only include sinks that are actually invoked in the application.
        List<String> allAppJars = new ArrayList<>();
        if (targetAppJars != null) allAppJars.addAll(targetAppJars);
        if (depAppJars != null) allAppJars.addAll(depAppJars);
        RuleManager ruleManager = new RuleManager(configManager.getConfig());
        String taintConfigPath = ruleManager.generateTaieConfig(entrySignatures, workspaceDir, allAppJars);
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
        //
        // Why only-app:true is safe here:
        //   With only-app:true, Tai-e skips return-value PFG edges for library methods.
        //   This would normally leave library factory method results (Runtime.getRuntime(),
        //   Connection.createStatement(), etc.) with empty pts, preventing virtual call
        //   edge creation to their subsequent sink calls.
        //   LibraryBridgePlugin compensates by injecting synthetic objects into those
        //   return variables via onNewCallEdge(), unblocking the call-edge chain.
        //
        // Why NOT cs:1-obj or removing only-app:
        //   cs:1-obj on 27K+ reachable classes causes exponential state explosion (OOM).
        //   Removing only-app causes full library analysis: 100K+ reachable methods,
        //   potentially 10-20 GB memory and 5-30 min runtime for Spring Boot projects.
        String ptaConfig = "pta=cs:ci;only-app:true;taint-config:" + taintConfigPath;
        args.add("-a");
        args.add(ptaConfig);

        logger.info("Running Tai-e with arguments: {}", String.join(" ", args));

        // Note: Main.main calls System.exit() by default in some Tai-e versions upon completion/error.
        // In library mode, we should ideally use Options.parse and run analyses manually,
        // or ensure Main.main is safe.
        // Let's manually parse and execute to avoid System.exit
        ptaConfig += ";implicit-entries:true";
        // Two custom plugins:
        //   JBSScanEntryPointPlugin  – injects discovered API controller methods as PTA
        //                              entry points so TaintAnalysis sees their parameters.
        //   LibraryBridgePlugin      – injects synthetic return objects for library factory
        //                              methods (Runtime.getRuntime, createStatement, etc.)
        //                              so that subsequent virtual calls on those objects can
        //                              create call edges despite only-app:true.
        ptaConfig += ";plugins:[com.jbytescanner.engine.JBSScanEntryPointPlugin,"
                   + "com.jbytescanner.engine.LibraryBridgePlugin]";
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

            // Build World using ResilientSootWorldBuilder which adds library exclusions
            // to prevent Soot from crashing on classes with missing optional dependencies.
            logger.info("Building Tai-e World with {} appClassPath + {} classPath entries...",
                    targetAppJars.size(), combinedLibs.size());
            long startTime = System.currentTimeMillis();
            List<String> scanPkgs = configManager.getConfig().getScanConfig().getScanPackages();
            Set<String> libExcludes = ResilientSootWorldBuilder.deriveLibExcludes(combinedLibs, scanPkgs);
            ResilientSootWorldBuilder worldBuilder = new ResilientSootWorldBuilder();
            worldBuilder.setExcludePatterns(libExcludes);
            worldBuilder.build(options, plan.analyses());
            long worldTime = System.currentTimeMillis() - startTime;
            logger.info("Tai-e World built in {} seconds.", worldTime / 1000);

            // Execute the analysis plan (runs PTA which internally triggers TaintAnalysis plugin)
            new pascal.taie.analysis.AnalysisManager(plan).execute();
            pascal.taie.config.LoggerConfigs.reconfigure();
        } catch (Throwable t) {
            // Catch Throwable (not just Exception) to capture Error types:
            // StackOverflowError, NoClassDefFoundError, OutOfMemoryError, etc.
            logger.error("Tai-e analysis failed: {}", t.toString());
            System.err.println("[ERROR] Tai-e analysis failed: " + t.getClass().getName() + ": " + t.getMessage());
            t.printStackTrace(System.err);
            return;
        }

        logger.info("Tai-e Analysis Finished.");

        // 4. Extract Taint Results
        // Tai-e writes TaintFlow entries to tai-e.log during TaintAnalysis.reportTaintFlows().
        // We parse this log file to extract source/sink information, which is more reliable
        // than trying to access World results (which get cleared by AnalysisManager post-analysis).
        List<Vulnerability> vulnerabilities = parseTaintFlowsFromLog(
                new File(workspaceDir, "tai-e.log"), ruleManager);

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

    /**
     * Parses TaintFlow entries from tai-e.log and converts them to Vulnerability objects.
     *
     * <p>Tai-e writes one line per TaintFlow in the format:
     * {@code TaintFlow{<sourceMethod>/paramIdx -> <container>[stmtIdx@Lline] invokeText/argIdx}}
     *
     * <p>This approach is more reliable than reading from World.get().getResult("pta")
     * because AnalysisManager clears PTA results from World after analysis completes
     * (when "pta" is not in keepResult set).
     */
    private List<Vulnerability> parseTaintFlowsFromLog(File taiELog, RuleManager ruleManager) {
        List<Vulnerability> result = new ArrayList<>();
        if (!taiELog.exists()) {
            logger.warn("tai-e.log not found at: {}", taiELog.getAbsolutePath());
            return result;
        }
        try {
            List<String> lines = Files.readAllLines(taiELog.toPath());
            for (String line : lines) {
                if (!line.contains("TaintFlow{")) continue;
                int idx = line.indexOf("TaintFlow{");
                Matcher m = TAINT_FLOW_PATTERN.matcher(line.substring(idx));
                if (!m.find()) continue;

                String sourceInner = m.group(1);    // e.g. "org.joychou.controller.Rce: java.lang.String CommandExec(java.lang.String)"
                String containerInner = m.group(3); // container method (may differ from source)
                String invokeText = m.group(4).trim(); // e.g. "$r3 = invokevirtual $r0.exec(cmd)"

                Vulnerability vuln = convertLogEntryToVuln(sourceInner, containerInner, invokeText, ruleManager);
                if (vuln != null) {
                    result.add(vuln);
                }
            }
        } catch (IOException e) {
            logger.error("Failed to read tai-e.log for taint flow extraction", e);
        }
        logger.info("Extracted {} vulnerabilities from tai-e.log.", result.size());
        return result;
    }

    /**
     * Converts a parsed TaintFlow log entry into a Vulnerability.
     *
     * <p>Strategy for resolving the sink method signature:
     * <ul>
     *   <li>{@code invokestatic ClassName.method(args)}: class name is explicit → exact match</li>
     *   <li>{@code invokevirtual receiver.method(args)}: only method name → match by method name</li>
     *   <li>{@code invokespecial receiver.&lt;init&gt;(args)}: constructor → infer type from arg
     *       variable name and source/container context</li>
     * </ul>
     */
    private Vulnerability convertLogEntryToVuln(String sourceInner, String containerInner,
                                                 String invokeText, RuleManager ruleManager) {
        String sourceMethodSig = "<" + sourceInner + ">";

        // Strip any LHS assignment prefix: "$r1 = invokestatic ..." → "invokestatic ..."
        String invoke = invokeText;
        int invokeKeyword = invokeText.indexOf("invoke");
        if (invokeKeyword > 0) {
            invoke = invokeText.substring(invokeKeyword);
        }

        String sinkMethodSig = resolveSinkSignature(invoke, sourceMethodSig,
                "<" + containerInner + ">", ruleManager);

        // Look up SinkRule for vuln type and metadata
        SinkRule sinkRule = sinkMethodSig != null ? ruleManager.getRuleForSink(sinkMethodSig) : null;
        String vulnType;
        if (sinkRule != null) {
            vulnType = sinkRule.getVulnType();
        } else {
            vulnType = inferVulnTypeFromInvoke(invoke, sourceMethodSig);
        }

        // Use the invoke text as the sink display string when no exact sig is found
        String sinkDisplay = sinkMethodSig != null ? sinkMethodSig : invoke;

        List<String> trace = new ArrayList<>();
        trace.add(sourceMethodSig + " (Source)");
        if (!containerInner.equals(sourceInner)) {
            trace.add("<" + containerInner + "> (Container)");
        }
        trace.add(sinkDisplay + " (Sink)");

        return new Vulnerability(vulnType, sourceMethodSig, sinkDisplay, trace, true, sinkRule);
    }

    /**
     * Resolves the configured sink method signature from an Tai-e IR invoke statement.
     */
    private String resolveSinkSignature(String invoke, String sourceSig, String containerSig,
                                         RuleManager ruleManager) {
        if (invoke.startsWith("invokestatic ")) {
            // Format: "invokestatic com.example.Class.method(args)"
            String rest = invoke.substring("invokestatic ".length());
            int paren = rest.indexOf('(');
            if (paren < 0) return null;
            String classMethod = rest.substring(0, paren); // "com.example.Class.method"
            int lastDot = classMethod.lastIndexOf('.');
            if (lastDot < 0) return null;
            String className = classMethod.substring(0, lastDot);
            String methodName = classMethod.substring(lastDot + 1);
            for (SinkRule rule : ruleManager.getSinks()) {
                if (rule.getSignature() == null) continue;
                if (rule.getSignature().contains("<" + className + ": ")
                        && rule.getSignature().contains(" " + methodName + "(")) {
                    return rule.getSignature();
                }
            }

        } else if (invoke.startsWith("invokevirtual ")) {
            // Format: "invokevirtual receiver.method(args)"
            String rest = invoke.substring("invokevirtual ".length());
            int dot = rest.indexOf('.');
            if (dot < 0) return null;
            int paren = rest.indexOf('(', dot);
            if (paren < 0) return null;
            String methodName = rest.substring(dot + 1, paren);
            for (SinkRule rule : ruleManager.getSinks()) {
                if (rule.getSignature() == null) continue;
                // Match " methodName(" to avoid false partial matches
                if (rule.getSignature().contains(" " + methodName + "(")) {
                    return rule.getSignature();
                }
            }

        } else if (invoke.startsWith("invokespecial ") && invoke.contains("<init>")) {
            // Constructor call — extract arg variable name for context hinting
            int paren = invoke.indexOf('(');
            int closeParen = invoke.indexOf(')');
            String argName = (paren >= 0 && closeParen > paren)
                    ? invoke.substring(paren + 1, closeParen).trim() : "";
            return resolveConstructorSink(argName, sourceSig, containerSig, ruleManager);
        }
        return null;
    }

    /**
     * Infers which constructor sink is being called based on argument name and context.
     * Disambiguates between java.net.URL (SSRF) and java.io.File (PathTraversal).
     */
    private String resolveConstructorSink(String argName, String sourceSig, String containerSig,
                                           RuleManager ruleManager) {
        String argLower = argName.toLowerCase();
        String srcLower = sourceSig.toLowerCase();
        String ctnLower = containerSig.toLowerCase();

        // Variable name hints
        boolean argSuggestsUrl = argLower.contains("url") || argLower.contains("uri");
        boolean argSuggestsFile = argLower.contains("file") || argLower.contains("path")
                || argLower.contains("img") || argLower.contains("filename");

        // Context hints
        boolean contextSuggestsUrl = srcLower.contains("ssrf") || srcLower.contains("urlwhite")
                || ctnLower.contains("httputils") || ctnLower.contains("urlconn")
                || ctnLower.contains("ssrfchecker") || ctnLower.contains("gethost")
                || ctnLower.contains("url2host") || ctnLower.contains("httpconn")
                || ctnLower.contains("encodeurl") || ctnLower.contains("imageio");
        boolean contextSuggestsFile = srcLower.contains("pathtraversal") || srcLower.contains("path")
                || ctnLower.contains("getimgbase64") || ctnLower.contains("getfileext")
                || ctnLower.contains("getnamewithoutext");

        boolean likelyUrl = argSuggestsUrl || (contextSuggestsUrl && !argSuggestsFile);
        boolean likelyFile = argSuggestsFile || (contextSuggestsFile && !argSuggestsUrl);

        for (SinkRule rule : ruleManager.getSinks()) {
            if (rule.getSignature() == null || !rule.getSignature().contains("<init>")) continue;
            if (likelyUrl && rule.getSignature().contains("java.net.URL")) return rule.getSignature();
            if (likelyFile && rule.getSignature().contains("java.io.File")) return rule.getSignature();
        }
        // Default to URL.<init> when ambiguous (SSRF is the more common constructor sink)
        if (!likelyFile) {
            for (SinkRule rule : ruleManager.getSinks()) {
                if (rule.getSignature() != null && rule.getSignature().contains("java.net.URL")
                        && rule.getSignature().contains("<init>")) {
                    return rule.getSignature();
                }
            }
        }
        return null;
    }

    /**
     * Infers vulnerability type from the invoke text when no matching SinkRule is found.
     */
    private String inferVulnTypeFromInvoke(String invoke, String sourceSig) {
        if (invoke.contains(".exec("))       return "RCE";
        if (invoke.contains(".evaluate("))   return "RCE";
        if (invoke.contains(".load("))       return "Deserialization";
        if (invoke.contains(".readValue("))  return "Deserialization";
        if (invoke.contains("Paths.get("))   return "PathTraversal";
        if (invoke.contains("JSON.parse"))   return "Deserialization";
        if (invoke.contains("<init>")) {
            String src = sourceSig.toLowerCase();
            if (src.contains("ssrf") || src.contains("url")) return "SSRF";
            if (src.contains("path") || src.contains("file")) return "PathTraversal";
            return "SSRF"; // default for constructor sinks
        }
        return "Unknown";
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
