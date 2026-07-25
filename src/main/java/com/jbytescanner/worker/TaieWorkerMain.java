package com.jbytescanner.worker;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jbytescanner.engine.JBSScanEntryPointPlugin;
import com.jbytescanner.engine.LibraryBridgePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pascal.taie.World;
import pascal.taie.WorldBuilder;
import pascal.taie.analysis.AnalysisManager;
import pascal.taie.config.AnalysisConfig;
import pascal.taie.config.AnalysisPlanner;
import pascal.taie.config.ConfigManager;
import pascal.taie.config.Configs;
import pascal.taie.config.LoggerConfigs;
import pascal.taie.config.Options;
import pascal.taie.config.Plan;
import pascal.taie.config.PlanConfig;

import java.io.File;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Child-JVM entry for Tai-e World / PTA / taint analysis.
 *
 * <p>Protocol:
 * <ol>
 *   <li>Main process writes {@code worker-request.json} and launches this class.</li>
 *   <li>Worker runs analysis with explicit heap / GC / heap-dump JVM flags.</li>
 *   <li>Worker writes {@code worker-result.json} then exits with a status code.</li>
 * </ol>
 *
 * <p>Exit codes: 0 success, 1 failure, 2 OOM, 3 timeout/cancelled.
 */
public final class TaieWorkerMain {

    public static final int EXIT_SUCCESS = 0;
    public static final int EXIT_FAILED = 1;
    public static final int EXIT_OOM = 2;
    public static final int EXIT_TIMEOUT = 3;

    private static final Logger logger = LoggerFactory.getLogger(TaieWorkerMain.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private TaieWorkerMain() {
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: TaieWorkerMain <request.json>");
            System.exit(EXIT_FAILED);
        }
        try {
            TaieWorkerRequest request = MAPPER.readValue(Path.of(args[0]).toFile(), TaieWorkerRequest.class);
            TaieWorkerResult result = runForHost(request);
            System.exit(result.exitCode);
        } catch (OutOfMemoryError oom) {
            throw oom;
        } catch (Throwable t) {
            t.printStackTrace(System.err);
            System.exit(EXIT_FAILED);
        }
    }

    /**
     * Execute analysis for the given request and write {@code worker-result.json}.
     * Used by the child JVM main and by in-process fallback from the host.
     * Does not call {@link System#exit(int)}.
     */
    public static TaieWorkerResult runForHost(TaieWorkerRequest request) {
        TaieWorkerResult result = new TaieWorkerResult();
        result.status = TaieWorkerResult.STATUS_FAILED;
        result.exitCode = EXIT_FAILED;
        long totalStart = System.currentTimeMillis();
        Path resultPath = null;
        try {
            result.batchId = request.batchId;
            result.executionMode = request.executionMode;
            Path outputDir = Path.of(request.outputDir != null ? request.outputDir : request.workspaceDir);
            Files.createDirectories(outputDir);
            resultPath = outputDir.resolve("worker-result.json");
            result.gcLogPath = System.getProperty("jbytescanner.worker.gcLog");
            result.heapDumpPath = System.getProperty("jbytescanner.worker.heapDump");
            result.taiELogPath = outputDir.resolve("tai-e.log").toString();

            runAnalysis(request, result);
            if (result.analysisCompleted) {
                result.status = TaieWorkerResult.STATUS_SUCCESS;
                result.exitCode = EXIT_SUCCESS;
            }
        } catch (OutOfMemoryError oom) {
            handleThrowable(result, oom, TaieWorkerResult.STATUS_OOM, EXIT_OOM);
            tryWriteResult(resultPath, result, totalStart);
            throw oom;
        } catch (Throwable t) {
            String status = isOomRelated(t)
                    ? TaieWorkerResult.STATUS_OOM
                    : TaieWorkerResult.STATUS_FAILED;
            int code = TaieWorkerResult.STATUS_OOM.equals(status) ? EXIT_OOM : EXIT_FAILED;
            handleThrowable(result, t, status, code);
        } finally {
            tryWriteResult(resultPath, result, totalStart);
        }
        return result;
    }

    private static void runAnalysis(TaieWorkerRequest request, TaieWorkerResult result) throws Exception {
        JBSScanEntryPointPlugin.entrySignatures =
                request.entrySignatures != null ? List.copyOf(request.entrySignatures) : List.of();
        JBSScanEntryPointPlugin.supplementalEntrySignatures =
                request.supplementalEntrySignatures != null
                        ? List.copyOf(request.supplementalEntrySignatures)
                        : List.of();
        JBSScanEntryPointPlugin.springServiceEntryFallback = request.springServiceEntryFallback;
        JBSScanEntryPointPlugin.capturedTaintFlows = null;

        List<String> args = new ArrayList<>();
        if (request.targetAppJars != null && !request.targetAppJars.isEmpty()) {
            args.add("--app-class-path");
            args.add(String.join(File.pathSeparator, request.targetAppJars));
        }
        if (request.classPathJars != null && !request.classPathJars.isEmpty()) {
            args.add("--class-path");
            args.add(String.join(File.pathSeparator, request.classPathJars));
        }
        args.add("--world-builder");
        args.add("pascal.taie.frontend.java.JavaWorldBuilder");
        args.add("--output-dir");
        args.add(request.outputDir != null ? request.outputDir : request.workspaceDir);

        String ptaConfig = "pta=cs:ci;only-app:true;taint-config:" + request.taintConfigPath
                + ";implicit-entries:true"
                + ";plugins:[" + JBSScanEntryPointPlugin.class.getName()
                + "," + LibraryBridgePlugin.class.getName() + "]";
        if (request.springAnalysis) {
            ptaConfig += ";spring:true";
        }
        // call-site-mode is already embedded in the generated taint-config YAML by
        // RuleManager (key call-site-mode). request.taintCallSiteMode is diagnostic only.
        args.add("-a");
        args.add(ptaConfig);

        logger.info("[worker] batch={} args={}", request.batchId, String.join(" ", args));

        Options options = Options.parse(args.toArray(new String[0]));
        LoggerConfigs.setOutput(options.getOutputDir());

        InputStream content = Configs.getAnalysisConfig();
        List<AnalysisConfig> analysisConfigs = AnalysisConfig.parseConfigs(content);
        ConfigManager mgr = new ConfigManager(analysisConfigs);
        AnalysisPlanner planner = new AnalysisPlanner(mgr, options.getKeepResult());
        List<PlanConfig> planConfigs = PlanConfig.readConfigs(options);
        mgr.overwriteOptions(planConfigs);
        Plan plan = planner.expandPlan(planConfigs, false);

        PhaseMetrics worldPhase = PhaseMetrics.start("world");
        result.phases.add(worldPhase);
        try {
            logger.info("[worker] Building Tai-e World (app={}, cp={})...",
                    request.targetAppJars == null ? 0 : request.targetAppJars.size(),
                    request.classPathJars == null ? 0 : request.classPathJars.size());
            WorldBuilder worldBuilder = options.getWorldBuilderClass().getConstructor().newInstance();
            worldBuilder.build(options);
            worldPhase.sample();
            result.worldCompleted = true;
            result.applicationClassCount = World.get().getClassHierarchy().applicationClasses().count();
            worldPhase.finish("SUCCESS", "applicationClasses=" + result.applicationClassCount);
            result.worldMs = worldPhase.durationMs;
            result.peakHeapBytes = Math.max(result.peakHeapBytes, worldPhase.peakHeapBytes);
            if (worldPhase.peakRssBytes != null) {
                result.peakRssBytes = maxLong(result.peakRssBytes, worldPhase.peakRssBytes);
            }
            logger.info("[worker] World built in {} ms, app classes={}",
                    worldPhase.durationMs, result.applicationClassCount);
        } catch (Throwable t) {
            worldPhase.finish("FAILED", t.toString());
            throw t;
        }

        PhaseMetrics ptaPhase = PhaseMetrics.start("pta");
        result.phases.add(ptaPhase);
        try {
            logger.info("[worker] Executing analysis plan...");
            new AnalysisManager(plan).execute();
            LoggerConfigs.reconfigure();
            ptaPhase.sample();
            result.analysisCompleted = true;
            ptaPhase.finish("SUCCESS", null);
            result.ptaMs = ptaPhase.durationMs;
            result.peakHeapBytes = Math.max(result.peakHeapBytes, ptaPhase.peakHeapBytes);
            if (ptaPhase.peakRssBytes != null) {
                result.peakRssBytes = maxLong(result.peakRssBytes, ptaPhase.peakRssBytes);
            }
            logger.info("[worker] Analysis finished in {} ms", ptaPhase.durationMs);
        } catch (Throwable t) {
            ptaPhase.finish(isOomRelated(t) ? "OOM" : "FAILED", t.toString());
            throw t;
        }
    }

    private static void handleThrowable(TaieWorkerResult result, Throwable t, String status, int exitCode) {
        result.status = status;
        result.exitCode = exitCode;
        result.errorClass = t.getClass().getName();
        result.errorMessage = t.getMessage();
        result.errorStackTrace = stackTrace(t);
        logger.error("[worker] analysis failed: {}", t.toString(), t);
        System.err.println("[ERROR] Tai-e worker failed: " + t.getClass().getName() + ": " + t.getMessage());
        t.printStackTrace(System.err);
    }

    private static void tryWriteResult(Path resultPath, TaieWorkerResult result, long totalStart) {
        if (resultPath == null) {
            return;
        }
        result.totalMs = Math.max(0, System.currentTimeMillis() - totalStart);
        try {
            Files.createDirectories(resultPath.getParent());
            MAPPER.writerWithDefaultPrettyPrinter().writeValue(resultPath.toFile(), result);
        } catch (Throwable writeError) {
            System.err.println("[ERROR] Failed to write worker-result.json: " + writeError);
            writeError.printStackTrace(System.err);
        }
    }

    private static boolean isOomRelated(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof OutOfMemoryError) {
                return true;
            }
            String name = c.getClass().getName();
            if (name.contains("OutOfMemory")) {
                return true;
            }
        }
        return false;
    }

    private static String stackTrace(Throwable t) {
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }

    private static Long maxLong(Long a, long b) {
        return a == null ? b : Math.max(a, b);
    }
}
