package com.jbytescanner.worker;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jbytescanner.config.ResourceBudget;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Spawns an isolated JVM running {@link TaieWorkerMain} under an explicit
 * {@link ResourceBudget}. Main process never shares a heap with Tai-e World/PTA.
 */
public class TaieWorkerLauncher {

    private static final Logger logger = LoggerFactory.getLogger(TaieWorkerLauncher.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final ResourceBudget budget;

    public TaieWorkerLauncher(ResourceBudget budget) {
        this.budget = budget != null ? budget : new ResourceBudget();
    }

    public TaieWorkerResult run(TaieWorkerRequest request, Path workerDir) throws Exception {
        Files.createDirectories(workerDir);
        // Isolate Tai-e outputs (options, TFG, logs, result) under the worker batch dir.
        request.outputDir = workerDir.toAbsolutePath().toString();
        if (request.workspaceDir == null) {
            request.workspaceDir = workerDir.getParent() != null
                    && workerDir.getParent().getParent() != null
                    ? workerDir.getParent().getParent().toAbsolutePath().toString()
                    : workerDir.toAbsolutePath().toString();
        }
        Path requestPath = workerDir.resolve("worker-request.json");
        Path resultPath = workerDir.resolve("worker-result.json");
        Files.deleteIfExists(resultPath);
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(requestPath.toFile(), request);

        Path heapDumpPath = workerDir.resolve("java_pid_oom.hprof");
        Path gcLogPath = workerDir.resolve("gc.log");

        List<String> command = buildCommand(requestPath, heapDumpPath, gcLogPath);
        logger.info("Launching Tai-e worker: {}", String.join(" ", command));

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(workerDir.toFile());
        pb.redirectErrorStream(true);

        long start = System.currentTimeMillis();
        Process process = pb.start();
        AtomicBoolean timedOut = new AtomicBoolean(false);

        Thread logPump = new Thread(() -> pumpOutput(process), "taie-worker-log");
        logPump.setDaemon(true);
        logPump.start();

        boolean finished;
        int timeoutMinutes = budget.getTimeoutMinutes();
        if (timeoutMinutes > 0) {
            finished = process.waitFor(timeoutMinutes, TimeUnit.MINUTES);
            if (!finished) {
                timedOut.set(true);
                logger.error("Tai-e worker exceeded timeout of {} minutes; destroying process", timeoutMinutes);
                process.destroyForcibly();
                process.waitFor(30, TimeUnit.SECONDS);
            }
        } else {
            process.waitFor();
            finished = true;
        }
        try {
            logPump.join(Duration.ofSeconds(5).toMillis());
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }

        int exitCode = finished ? process.exitValue() : TaieWorkerMain.EXIT_TIMEOUT;
        TaieWorkerResult result = readResult(resultPath, exitCode, timedOut.get(),
                heapDumpPath, gcLogPath, start);
        logger.info("Tai-e worker finished: status={}, exitCode={}, worldMs={}, ptaMs={}, peakHeapMB={}",
                result.status, result.exitCode, result.worldMs, result.ptaMs,
                result.peakHeapBytes / (1024 * 1024));
        return result;
    }

    List<String> buildCommand(Path requestPath, Path heapDumpPath, Path gcLogPath) {
        List<String> cmd = new ArrayList<>();
        cmd.add(javaBinary());
        cmd.add("-Xmx" + Math.max(256, budget.getMaxHeapMb()) + "m");
        int minHeap = budget.effectiveMinHeapMb();
        if (minHeap > 0) {
            cmd.add("-Xms" + minHeap + "m");
        }
        if (budget.isHeapDumpOnOom()) {
            cmd.add("-XX:+HeapDumpOnOutOfMemoryError");
            cmd.add("-XX:HeapDumpPath=" + heapDumpPath.toAbsolutePath());
        }
        if (budget.isGcLog()) {
            // Unified logging works on JDK 9+; JByteScanner targets modern JDKs.
            cmd.add("-Xlog:gc*:file=" + gcLogPath.toAbsolutePath() + ":time,uptime,level,tags");
        }
        cmd.add("-Djbytescanner.worker.heapDump=" + heapDumpPath.toAbsolutePath());
        cmd.add("-Djbytescanner.worker.gcLog=" + gcLogPath.toAbsolutePath());
        // Avoid reusing a corrupted heap after OOM inside the worker.
        cmd.add("-XX:+ExitOnOutOfMemoryError");
        cmd.add("-cp");
        cmd.add(resolveClasspath());
        cmd.add(TaieWorkerMain.class.getName());
        cmd.add(requestPath.toAbsolutePath().toString());
        return cmd;
    }

    static String javaBinary() {
        String javaHome = System.getProperty("java.home");
        if (javaHome != null && !javaHome.isBlank()) {
            Path bin = Path.of(javaHome, "bin",
                    File.separatorChar == '\\' ? "java.exe" : "java");
            if (Files.isExecutable(bin) || Files.exists(bin)) {
                return bin.toAbsolutePath().toString();
            }
        }
        return "java";
    }

    static String resolveClasspath() {
        String cp = System.getProperty("java.class.path");
        if (cp != null && !cp.isBlank()) {
            return cp;
        }
        // Fallback for unusual launchers: use the protection domain of this class.
        try {
            Path location = Path.of(TaieWorkerLauncher.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            return location.toAbsolutePath().toString();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot resolve classpath for Tai-e worker", e);
        }
    }

    private static void pumpOutput(Process process) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                logger.info("[worker-out] {}", line);
            }
        } catch (Exception e) {
            logger.debug("Worker output pump stopped: {}", e.toString());
        }
    }

    private TaieWorkerResult readResult(Path resultPath, int exitCode, boolean timedOut,
                                        Path heapDumpPath, Path gcLogPath, long startMs) {
        TaieWorkerResult result = null;
        if (Files.exists(resultPath)) {
            try {
                result = MAPPER.readValue(resultPath.toFile(), TaieWorkerResult.class);
            } catch (Exception e) {
                logger.error("Failed to parse worker-result.json", e);
            }
        }
        if (result == null) {
            result = new TaieWorkerResult();
            result.status = timedOut
                    ? TaieWorkerResult.STATUS_TIMEOUT
                    : (exitCode == TaieWorkerMain.EXIT_OOM
                    ? TaieWorkerResult.STATUS_OOM
                    : TaieWorkerResult.STATUS_FAILED);
            result.errorMessage = timedOut
                    ? "Worker process timed out"
                    : "Worker exited without writing worker-result.json (exitCode=" + exitCode + ")";
        }
        result.exitCode = exitCode;
        if (timedOut) {
            result.status = TaieWorkerResult.STATUS_TIMEOUT;
            result.exitCode = TaieWorkerMain.EXIT_TIMEOUT;
        } else if (exitCode == TaieWorkerMain.EXIT_OOM
                && !TaieWorkerResult.STATUS_OOM.equals(result.status)) {
            result.status = TaieWorkerResult.STATUS_OOM;
        } else if (exitCode == 0 && result.status == null) {
            result.status = TaieWorkerResult.STATUS_SUCCESS;
        }
        if (result.heapDumpPath == null && Files.exists(heapDumpPath)) {
            result.heapDumpPath = heapDumpPath.toAbsolutePath().toString();
        }
        if (result.gcLogPath == null && Files.exists(gcLogPath)) {
            result.gcLogPath = gcLogPath.toAbsolutePath().toString();
        }
        if (result.totalMs <= 0) {
            result.totalMs = Math.max(0, System.currentTimeMillis() - startMs);
        }
        return result;
    }
}
