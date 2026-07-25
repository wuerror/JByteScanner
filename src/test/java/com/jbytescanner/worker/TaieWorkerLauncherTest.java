package com.jbytescanner.worker;

import com.jbytescanner.config.ResourceBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TaieWorkerLauncherTest {

    @TempDir
    Path tempDir;

    @Test
    void buildCommandIncludesHeapDumpGcAndExplicitXmx() {
        ResourceBudget budget = new ResourceBudget();
        budget.setMaxHeapMb(4096);
        budget.setMinHeapMb(512);
        budget.setGcLog(true);
        budget.setHeapDumpOnOom(true);

        TaieWorkerLauncher launcher = new TaieWorkerLauncher(budget);
        Path request = tempDir.resolve("worker-request.json");
        Path heapDump = tempDir.resolve("java_pid_oom.hprof");
        Path gcLog = tempDir.resolve("gc.log");

        List<String> cmd = launcher.buildCommand(request, heapDump, gcLog);

        assertTrue(cmd.get(0).toLowerCase().contains("java"));
        assertTrue(cmd.contains("-Xmx4096m"));
        assertTrue(cmd.contains("-Xms512m"));
        assertTrue(cmd.stream().anyMatch(a -> a.startsWith("-XX:HeapDumpPath=")));
        assertTrue(cmd.stream().anyMatch(a -> a.startsWith("-Xlog:gc")));
        assertTrue(cmd.contains("-XX:+ExitOnOutOfMemoryError"));
        assertTrue(cmd.contains(TaieWorkerMain.class.getName()));
        assertEquals(request.toAbsolutePath().toString(), cmd.get(cmd.size() - 1));
    }

    @Test
    void budgetSnapshotDefaultsAreWorkerEnabled() {
        ResourceBudget budget = new ResourceBudget();
        assertTrue(budget.isWorkerEnabled());
        assertTrue(!budget.isAllowInProcessFallback());
        assertTrue(budget.isHeapDumpOnOom());
        assertTrue(budget.isGcLog());
        assertEquals(8192, budget.getMaxHeapMb());
        assertEquals("single", budget.getExecutionMode());
    }

    @Test
    void benchmarkWrittenFromWorkerResult() throws Exception {
        TaieWorkerResult result = new TaieWorkerResult();
        result.status = TaieWorkerResult.STATUS_OOM;
        result.exitCode = TaieWorkerMain.EXIT_OOM;
        result.worldCompleted = false;
        result.executionMode = "single";
        result.errorClass = "java.lang.OutOfMemoryError";
        result.errorMessage = "Java heap space";
        result.peakHeapBytes = 7L * 1024 * 1024 * 1024;
        result.heapDumpPath = tempDir.resolve("java_pid_oom.hprof").toString();

        BenchmarkMetrics metrics = BenchmarkMetrics.fromWorker(result, java.util.Map.of(
                "workerEnabled", true,
                "maxHeapMb", 8192
        ));
        metrics.write(tempDir);

        Path out = tempDir.resolve("benchmark.json");
        assertTrue(Files.exists(out));
        String json = Files.readString(out);
        assertTrue(json.contains("\"workerStatus\" : \"OOM\"") || json.contains("\"workerStatus\": \"OOM\"")
                || json.contains("\"workerStatus\" : \"OOM\"") || json.contains("OOM"));
        assertTrue(json.contains("8192"));
        assertEquals(1, metrics.partitionsFailed);
        assertEquals(0, metrics.partitionsCompleted);
    }
}
