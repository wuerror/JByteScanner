package com.jbytescanner.engine;

import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.config.ResourceBudget;
import com.jbytescanner.config.ScanConfig;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.finding.FindingPipeline;
import com.jbytescanner.finding.FindingSidecarWriter;
import com.jbytescanner.finding.PipelineResult;
import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import com.jbytescanner.worker.BenchmarkMetrics;
import com.jbytescanner.worker.CapturedTaintFlow;
import com.jbytescanner.worker.TaieWorkerLauncher;
import com.jbytescanner.worker.TaieWorkerMain;
import com.jbytescanner.worker.TaieWorkerRequest;
import com.jbytescanner.worker.TaieWorkerResult;
import pascal.taie.World;
import pascal.taie.ir.stmt.Invoke;
import pascal.taie.ir.stmt.Stmt;
import pascal.taie.language.classes.JMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TaintEngine {
    private static final Logger logger = LoggerFactory.getLogger(TaintEngine.class);

    // Matches both parameter sources (/0) and call/receiver sources (/result, /base):
    // Parameter source: TaintFlow{<sourceMethod>/0 -> ...}
    // Call source:      TaintFlow{<sourceMethod>[stmt@line] invoke/result -> ...}
    private static final Pattern TAINT_FLOW_PATTERN = Pattern.compile(
            "TaintFlow\\{<(.+?)>(?:\\[(\\d+)@L\\d+\\] .*?)?"
                    + "/(\\d+|base|result) -> <(.+?)>"
                    + "\\[(\\d+)@L\\d+\\] (.*?)/(\\d+|base|result)\\}");

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

        // Routes stay 1:N (same Java method may map to many HTTP paths).
        // PTA entry points and param sources use EntryPointKey = full method signature.
        List<String> rawEntrySignatures = new ArrayList<>(routes.size());
        for (ApiRoute route : routes) {
            rawEntrySignatures.add(String.format("<%s: %s>", route.getClassName(), route.getMethodSig()));
        }
        CanonicalIdentity.DedupResult entryDedup = CanonicalIdentity.dedupeOrdered(rawEntrySignatures);
        List<String> entrySignatures = new ArrayList<>(entryDedup.uniqueItems());
        logger.info("EntryPointKey dedup: raw={}, unique={}, duplicate={}; top duplicates: {}",
                entryDedup.raw(), entryDedup.unique(), entryDedup.duplicate(),
                entryDedup.formatTopDuplicates(10));

        // Publish unique entry signatures to the PTA plugin BEFORE any Tai-e World is built.
        // JBSScanEntryPointPlugin.onStart() reads this static field when PTA initializes.
        JBSScanEntryPointPlugin.entrySignatures = entrySignatures;
        JBSScanEntryPointPlugin.springServiceEntryFallback =
                configManager.getConfig().getScanConfig() == null
                        || configManager.getConfig().getScanConfig().isSpringServiceEntryFallback();

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
        ExpansionMetrics expansionMetrics = ruleManager.getLastExpansionMetrics();
        try {
            expansionMetrics.write(workspaceDir.toPath());
        } catch (Exception e) {
            logger.warn("Failed to write expansion-metrics.json: {}", e.toString());
        }

        // 3. Run Tai-e World/PTA in an isolated worker JVM (P0.3), with optional
        // in-process fallback for tests when the worker classpath is unavailable.
        List<String> combinedLibs = new ArrayList<>();
        if (libJars != null) {
            combinedLibs.addAll(libJars);
        }
        if (depAppJars != null) {
            combinedLibs.addAll(depAppJars);
        }

        ScanConfig scanConfig = configManager.getConfig().getScanConfig();
        ResourceBudget budget = scanConfig != null
                ? scanConfig.getResourceBudget()
                : new ResourceBudget();

        TaieWorkerRequest workerRequest = new TaieWorkerRequest();
        workerRequest.workspaceDir = workspaceDir.getAbsolutePath();
        workerRequest.outputDir = workspaceDir.getAbsolutePath();
        if (targetAppJars != null) {
            workerRequest.targetAppJars.addAll(targetAppJars);
        }
        workerRequest.classPathJars.addAll(combinedLibs);
        workerRequest.entrySignatures.addAll(entrySignatures);
        if (JBSScanEntryPointPlugin.supplementalEntrySignatures != null) {
            workerRequest.supplementalEntrySignatures.addAll(
                    JBSScanEntryPointPlugin.supplementalEntrySignatures);
        }
        workerRequest.taintConfigPath = taintConfigPath;
        workerRequest.springAnalysis = scanConfig == null || scanConfig.isSpringAnalysis();
        workerRequest.springServiceEntryFallback =
                scanConfig == null || scanConfig.isSpringServiceEntryFallback();
        workerRequest.taintCallSiteMode = scanConfig == null || scanConfig.isTaintCallSiteMode();
        workerRequest.batchId = "single";
        workerRequest.executionMode = budget.getExecutionMode() != null
                ? budget.getExecutionMode()
                : "single";

        TaieWorkerResult workerResult;
        try {
            workerResult = executeAnalysis(workerRequest, budget);
        } catch (Exception e) {
            logger.error("Failed to launch Tai-e analysis", e);
            writeBenchmark(null, budget, expansionMetrics, null);
            return;
        }
        mergeInjectMetrics(expansionMetrics, workerResult);
        try {
            expansionMetrics.write(workspaceDir.toPath());
        } catch (Exception e) {
            logger.warn("Failed to update expansion-metrics.json: {}", e.toString());
        }
        if (workerResult == null || !TaieWorkerResult.STATUS_SUCCESS.equals(workerResult.status)) {
            logWorkerFailure(workerResult);
            writeBenchmark(workerResult, budget, expansionMetrics, null);
            return;
        }

        logger.info("Tai-e Analysis Finished. worldMs={}, ptaMs={}, peakHeapMB={}",
                workerResult.worldMs, workerResult.ptaMs,
                workerResult.peakHeapBytes / (1024 * 1024));

        // 4. Structured flows → P0.6 FindingPipeline (filter / aggregate / score)
        List<CapturedTaintFlow> rawFlows;
        if (workerResult.protocolVersion >= 2) {
            rawFlows = workerResult.taintFlows != null ? workerResult.taintFlows : List.of();
        } else {
            logger.warn("Tai-e worker protocol v{} does not provide structured taint flows; "
                            + "falling back to legacy tai-e.log parsing + scoring.",
                    workerResult.protocolVersion);
            File taiELog = workerResult.taiELogPath != null
                    ? new File(workerResult.taiELogPath)
                    : new File(workspaceDir, "tai-e.log");
            List<Vulnerability> legacy = parseTaintFlowsFromLog(taiELog, ruleManager);
            com.jbytescanner.config.AuthConfig authConfig = scanConfig != null
                    ? scanConfig.getAuthConfig() : null;
            if (authConfig == null) {
                authConfig = new com.jbytescanner.config.AuthConfig();
            }
            com.jbytescanner.score.AuthDetector authDetector =
                    new com.jbytescanner.score.AuthDetector(authConfig);
            com.jbytescanner.score.VulnScorer scorer =
                    new com.jbytescanner.score.VulnScorer(authDetector);
            for (Vulnerability vuln : legacy) {
                ApiRoute route = findRoute(routes, vuln.getSourceMethod());
                scorer.score(vuln, route);
            }
            writeBenchmark(workerResult, budget, expansionMetrics, null);
            if (!legacy.isEmpty()) {
                new com.jbytescanner.report.SarifReporter(workspaceDir).generate(legacy);
                new com.jbytescanner.report.PoCReporter(workspaceDir).generate(legacy, routes);
            }
            return;
        }

        PipelineResult pipelineResult;
        try {
            FindingPipeline pipeline = new FindingPipeline(
                    ruleManager, scanConfig, routes);
            pipelineResult = pipeline.process(rawFlows);
        } catch (IllegalStateException e) {
            logger.error("Finding pipeline failed; refusing ambiguous report.", e);
            writeBenchmark(workerResult, budget, expansionMetrics, null);
            throw e;
        }

        FindingSidecarWriter.write(workspaceDir, pipelineResult,
                scanConfig != null ? scanConfig.getNoiseFilter()
                        : new com.jbytescanner.config.NoiseFilterConfig(),
                rawFlows);
        writeBenchmark(workerResult, budget, expansionMetrics, pipelineResult);

        int maxInst = scanConfig != null
                ? scanConfig.getNoiseFilter().getMaxInstancesInSarif() : 10;
        List<Vulnerability> vulnerabilities =
                FindingPipeline.toVulnerabilities(pipelineResult.mainFindings, maxInst);
        logger.info("Pipeline main findings: {} (raw flows: {}, suppressed: {}, low: {})",
                vulnerabilities.size(), pipelineResult.flowsRaw,
                pipelineResult.suppressedFindings.size(),
                pipelineResult.lowConfidenceFindings.size());

        // 5. Generate Report (always write result.sarif, even if empty run)
        com.jbytescanner.report.SarifReporter reporter =
                new com.jbytescanner.report.SarifReporter(workspaceDir);
        reporter.generate(vulnerabilities);
        if (vulnerabilities.isEmpty()) {
            logger.info("No main-SARIF vulnerabilities after P0.6 pipeline (empty result.sarif written).");
        } else {
            logger.info("Generating Smart PoC payloads...");
            com.jbytescanner.report.PoCReporter pocReporter =
                    new com.jbytescanner.report.PoCReporter(workspaceDir);
            pocReporter.generate(vulnerabilities, routes);
        }
    }

    /**
     * Converts worker-captured Tai-e flows using the exact configured sink method
     * carried by Tai-e's Sink object. No opcode, receiver-name, or method-name
     * inference is performed here.
     */
    static List<Vulnerability> convertCapturedFlows(List<CapturedTaintFlow> flows,
                                                     RuleManager ruleManager) {
        List<Vulnerability> result = new ArrayList<>();
        if (flows == null || flows.isEmpty()) {
            return result;
        }

        for (CapturedTaintFlow flow : flows) {
            SinkRule sinkRule = findStructuredSinkRule(flow, ruleManager);
            if (sinkRule == null) {
                throw new IllegalStateException(String.format(
                        "No SinkRule for captured flow: configured=%s, declared=%s, "
                                + "resolved=%s, container=%s, stmt=%d, invoke=%s",
                        flow.sinkRuleSignature, flow.declaredSinkSignature,
                        flow.resolvedSinkSignature, flow.sinkContainerSignature,
                        flow.sinkStmtIndex, flow.invokeText));
            }

            String sourceDisplay = firstNonBlank(
                    flow.sourceContainerSignature, flow.sourceRuleSignature, "<unknown-source>");
            String sinkDisplay = sinkRule.getSignature();

            List<String> trace = new ArrayList<>();
            trace.add(sourceDisplay + " (Source)");
            if (flow.sinkContainerSignature != null
                    && !flow.sinkContainerSignature.isBlank()
                    && !flow.sinkContainerSignature.equals(sourceDisplay)) {
                String location = flow.sinkContainerSignature;
                if (flow.sinkLineNumber >= 0) {
                    location += " @L" + flow.sinkLineNumber;
                }
                trace.add(location + " (Container)");
            }
            trace.add(sinkDisplay + " (Sink)");

            result.add(new Vulnerability(
                    sinkRule.getVulnType(),
                    sourceDisplay,
                    sinkDisplay,
                    trace,
                    true,
                    sinkRule));
        }
        return result;
    }

    private static SinkRule findStructuredSinkRule(CapturedTaintFlow flow,
                                                   RuleManager ruleManager) {
        if (flow == null) {
            return null;
        }
        String[] candidates = {
                flow.sinkRuleSignature,
                flow.declaredSinkSignature,
                flow.resolvedSinkSignature
        };
        for (String candidate : candidates) {
            if (candidate == null || candidate.isBlank()) {
                continue;
            }
            SinkRule rule = ruleManager.getRuleForSink(candidate);
            if (rule != null) {
                return rule;
            }
        }
        return null;
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
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
            List<String> lines = readLogLinesLenient(taiELog.toPath());
            for (String line : lines) {
                if (!line.contains("TaintFlow{")) continue;
                ParsedTaintFlow flow = parseTaintFlowLine(line);
                if (flow == null) continue;

                Vulnerability vuln = convertLogEntryToVuln(
                        flow.sourceMethod(), flow.containerMethod(), flow.sinkStmtIndex(),
                        flow.invokeText(), ruleManager);
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
     * Read text logs written by Tai-e / local tools without failing on mixed encodings.
     * Windows hosts often emit GBK/platform-default bytes while the JVM default reader
     * is UTF-8, which previously aborted the entire flow extraction with
     * {@link java.nio.charset.MalformedInputException}.
     */
    static List<String> readLogLinesLenient(Path path) throws IOException {
        byte[] raw = Files.readAllBytes(path);
        Charset[] candidates = new Charset[]{
                StandardCharsets.UTF_8,
                Charset.defaultCharset(),
                Charset.forName("GBK")
        };
        for (Charset cs : candidates) {
            try {
                var decoder = cs.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT);
                String text = decoder.decode(java.nio.ByteBuffer.wrap(raw)).toString();
                return text.lines().toList();
            } catch (CharacterCodingException ignored) {
                // try next charset
            } catch (IllegalArgumentException ignored) {
                // charset not available
            }
        }
        var decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        String text = decoder.decode(java.nio.ByteBuffer.wrap(raw)).toString();
        return text.lines().toList();
    }

    /**
     * Parses one Tai-e TaintFlow log line. Method signatures may themselves contain
     * angle brackets (notably constructors named {@code <init>}), so the signature
     * groups cannot stop at the first {@code '>'} character.
     */
    static ParsedTaintFlow parseTaintFlowLine(String line) {
        if (line == null) return null;
        int idx = line.indexOf("TaintFlow{");
        if (idx < 0) return null;
        Matcher matcher = TAINT_FLOW_PATTERN.matcher(line.substring(idx));
        if (!matcher.find()) return null;
        return new ParsedTaintFlow(
                matcher.group(1),
                matcher.group(4),
                Integer.parseInt(matcher.group(5)),
                matcher.group(6).trim());
    }

    record ParsedTaintFlow(String sourceMethod, String containerMethod,
                           int sinkStmtIndex, String invokeText) {
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
                                                 int sinkStmtIndex, String invokeText,
                                                 RuleManager ruleManager) {
        String sourceMethodSig = "<" + sourceInner + ">";

        // Strip any LHS assignment prefix: "$r1 = invokestatic ..." → "invokestatic ..."
        String invoke = invokeText;
        int invokeKeyword = invokeText.indexOf("invoke");
        if (invokeKeyword > 0) {
            invoke = invokeText.substring(invokeKeyword);
        }

        String containerSig = "<" + containerInner + ">";
        // IR resolution needs a live Tai-e World. Worker mode builds World only in
        // the child JVM, so the host must not call World.get() after the worker exits.
        String sinkMethodSig = null;
        if (isHostWorldAvailable()) {
            sinkMethodSig = resolveSinkSignatureFromIR(
                    containerSig, sinkStmtIndex, ruleManager);
        }
        if (sinkMethodSig == null) {
            sinkMethodSig = resolveSinkSignature(
                    invoke, sourceMethodSig, containerSig, ruleManager);
        }

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
     * True when this JVM still holds a Tai-e World (in-process analysis path only).
     * Worker mode leaves the host without a World; IR-based sink resolution must be skipped.
     */
    private static boolean isHostWorldAvailable() {
        try {
            return World.get() != null;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Resolves the sink from the exact Tai-e IR statement recorded in TaintFlow.
     * This avoids ambiguous method-name-only matching (for example GroovyShell.parse
     * versus JSON.parse) for virtual calls whose textual receiver is only a local variable.
     *
     * <p>Only safe when {@link #isHostWorldAvailable()} is true (in-process path).
     */
    private String resolveSinkSignatureFromIR(String containerSig, int stmtIndex,
                                              RuleManager ruleManager) {
        try {
            JMethod container = JBSScanEntryPointPlugin.resolveMethod(
                    World.get().getClassHierarchy(), containerSig);
            if (container == null || container.isAbstract() || container.isNative()) {
                return null;
            }
            Stmt stmt = container.getIR().getStmt(stmtIndex);
            if (!(stmt instanceof Invoke invoke)) {
                return null;
            }
            JMethod target = invoke.getMethodRef().resolveNullable();
            if (target != null && ruleManager.getRuleForSink(target.getSignature()) != null) {
                return target.getSignature();
            }
            String declaredRef = invoke.getMethodRef().toString();
            if (ruleManager.getRuleForSink(declaredRef) != null) {
                return declaredRef;
            }
        } catch (RuntimeException e) {
            logger.debug("Could not resolve sink from IR statement {} in {}",
                    stmtIndex, containerSig, e);
        }
        return null;
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


    private TaieWorkerResult executeAnalysis(TaieWorkerRequest request, ResourceBudget budget) throws Exception {
        if (budget.isWorkerEnabled()) {
            Path workerDir = workspaceDir.toPath().resolve("worker").resolve(request.batchId);
            try {
                return new TaieWorkerLauncher(budget).run(request, workerDir);
            } catch (Exception e) {
                if (!budget.isAllowInProcessFallback()) {
                    throw e;
                }
                logger.warn("Worker launch failed; falling back to in-process analysis: {}", e.toString());
            }
        } else {
            logger.info("resource_budget.worker_enabled=false; running Tai-e in-process");
        }
        return runInProcess(request);
    }

    /**
     * In-process path used by unit tests and emergency fallback. Still records phase
     * metrics, but does not isolate OOM from the host JVM.
     */
    private TaieWorkerResult runInProcess(TaieWorkerRequest request) {
        return TaieWorkerMain.runForHost(request);
    }

    private void logWorkerFailure(TaieWorkerResult workerResult) {
        if (workerResult == null) {
            logger.error("Tai-e worker returned no result");
            return;
        }
        logger.error("Tai-e worker failed: status={}, exitCode={}, error={}: {}",
                workerResult.status, workerResult.exitCode,
                workerResult.errorClass, workerResult.errorMessage);
        if (workerResult.errorStackTrace != null) {
            logger.error("Worker stack trace:\n{}", workerResult.errorStackTrace);
        }
        if (workerResult.heapDumpPath != null) {
            logger.error("Heap dump (if produced): {}", workerResult.heapDumpPath);
        }
        if (workerResult.gcLogPath != null) {
            logger.error("GC log: {}", workerResult.gcLogPath);
        }
        System.err.println("[ERROR] Tai-e analysis failed in worker: status="
                + workerResult.status + " " + workerResult.errorClass + ": "
                + workerResult.errorMessage);
        if (workerResult.errorStackTrace != null) {
            System.err.println(workerResult.errorStackTrace);
        }
    }


    private void mergeInjectMetrics(ExpansionMetrics expansionMetrics, TaieWorkerResult workerResult) {
        if (expansionMetrics == null) {
            return;
        }
        if (workerResult != null && workerResult.expansionInject != null
                && !workerResult.expansionInject.isEmpty()) {
            applyInjectMap(expansionMetrics, workerResult.expansionInject);
            return;
        }
        if (JBSScanEntryPointPlugin.lastInjectMetrics != null
                && JBSScanEntryPointPlugin.lastInjectMetrics.entryCandidates > 0) {
            ExpansionMetrics inj = JBSScanEntryPointPlugin.lastInjectMetrics;
            expansionMetrics.entryCandidates = inj.entryCandidates;
            expansionMetrics.entryInjected = inj.entryInjected;
            expansionMetrics.entryMethodIdentityDupSkipped = inj.entryMethodIdentityDupSkipped;
            expansionMetrics.entryUnresolved = inj.entryUnresolved;
            expansionMetrics.entryNoBodySkipped = inj.entryNoBodySkipped;
            expansionMetrics.supplementalEntriesInjected = inj.supplementalEntriesInjected;
            expansionMetrics.supplementalEntriesSkipped = inj.supplementalEntriesSkipped;
            expansionMetrics.serviceFallbackClasses = inj.serviceFallbackClasses;
            expansionMetrics.serviceFallbackMethodsInjected = inj.serviceFallbackMethodsInjected;
            expansionMetrics.capturedTaintFlows = inj.capturedTaintFlows;
        }
    }

    private static void applyInjectMap(ExpansionMetrics m, Map<String, Object> map) {
        m.entryCandidates = intVal(map.get("entryCandidates"), m.entryCandidates);
        m.entryInjected = intVal(map.get("entryInjected"), m.entryInjected);
        m.entryMethodIdentityDupSkipped = intVal(map.get("entryMethodIdentityDupSkipped"),
                m.entryMethodIdentityDupSkipped);
        m.entryUnresolved = intVal(map.get("entryUnresolved"), m.entryUnresolved);
        m.entryNoBodySkipped = intVal(map.get("entryNoBodySkipped"), m.entryNoBodySkipped);
        m.supplementalEntriesInjected = intVal(map.get("supplementalEntriesInjected"),
                m.supplementalEntriesInjected);
        m.supplementalEntriesSkipped = intVal(map.get("supplementalEntriesSkipped"),
                m.supplementalEntriesSkipped);
        m.serviceFallbackClasses = intVal(map.get("serviceFallbackClasses"), m.serviceFallbackClasses);
        m.serviceFallbackMethodsInjected = intVal(map.get("serviceFallbackMethodsInjected"),
                m.serviceFallbackMethodsInjected);
        if (map.get("capturedTaintFlows") != null) {
            m.capturedTaintFlows = intVal(map.get("capturedTaintFlows"), 0);
        }
    }

    private static int intVal(Object o, int defaultVal) {
        if (o instanceof Number n) {
            return n.intValue();
        }
        if (o != null) {
            try {
                return Integer.parseInt(o.toString());
            } catch (NumberFormatException ignored) {
                return defaultVal;
            }
        }
        return defaultVal;
    }

    private void writeBenchmark(TaieWorkerResult workerResult, ResourceBudget budget,
                                ExpansionMetrics expansionMetrics,
                                PipelineResult pipelineResult) {
        try {
            Map<String, Object> snap = new LinkedHashMap<>();
            snap.put("workerEnabled", budget.isWorkerEnabled());
            snap.put("maxHeapMb", budget.getMaxHeapMb());
            snap.put("minHeapMb", budget.getMinHeapMb());
            snap.put("timeoutMinutes", budget.getTimeoutMinutes());
            snap.put("gcLog", budget.isGcLog());
            snap.put("heapDumpOnOom", budget.isHeapDumpOnOom());
            snap.put("executionMode", budget.getExecutionMode());
            BenchmarkMetrics metrics = BenchmarkMetrics.fromWorker(workerResult, snap);
            if (expansionMetrics != null) {
                metrics.expansion.putAll(expansionMetrics.asMap());
            }
            if (pipelineResult != null) {
                metrics.expansion.putAll(pipelineResult.toBenchmarkMap());
            }
            metrics.write(workspaceDir.toPath());
        } catch (Exception e) {
            logger.warn("Failed to write benchmark.json: {}", e.toString());
        }
    }

    private List<ApiRoute> loadEntryPoints(File apiFile) {
        List<ApiRoute> routes = new ArrayList<>();
        try {
            List<String> lines = readLogLinesLenient(apiFile.toPath());
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
