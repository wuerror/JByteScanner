package com.jbytescanner.worker;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal {@code benchmark.json} writer for P0.3 resource and phase metrics.
 * Extended by later milestones (coverage, findings, partitions).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class BenchmarkMetrics {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @JsonProperty("executionMode")
    public String executionMode;

    @JsonProperty("resourceBudget")
    public Map<String, Object> resourceBudget = new LinkedHashMap<>();

    @JsonProperty("partitionsTotal")
    public int partitionsTotal = 1;

    @JsonProperty("partitionsCompleted")
    public int partitionsCompleted;

    @JsonProperty("partitionsFailed")
    public int partitionsFailed;

    @JsonProperty("worldCompleted")
    public boolean worldCompleted;

    @JsonProperty("analysisCompleted")
    public boolean analysisCompleted;

    @JsonProperty("worldMs")
    public long worldMs;

    @JsonProperty("ptaMs")
    public long ptaMs;

    @JsonProperty("tfgMs")
    public Long tfgMs;

    @JsonProperty("reportMs")
    public Long reportMs;

    @JsonProperty("peakHeapBytes")
    public long peakHeapBytes;

    @JsonProperty("peakRssBytes")
    public Long peakRssBytes;

    @JsonProperty("workerStatus")
    public String workerStatus;

    @JsonProperty("workerExitCode")
    public Integer workerExitCode;

    @JsonProperty("heapDumpPath")
    public String heapDumpPath;

    @JsonProperty("gcLogPath")
    public String gcLogPath;

    @JsonProperty("errorClass")
    public String errorClass;

    @JsonProperty("errorMessage")
    public String errorMessage;

    @JsonProperty("phases")
    public List<PhaseMetrics> phases = new ArrayList<>();

    @JsonProperty("expansion")
    public Map<String, Object> expansion = new LinkedHashMap<>();

    public static BenchmarkMetrics fromWorker(TaieWorkerResult worker,
                                              Map<String, Object> budgetSnapshot) {
        BenchmarkMetrics m = new BenchmarkMetrics();
        if (budgetSnapshot != null) {
            m.resourceBudget.putAll(budgetSnapshot);
        }
        if (worker == null) {
            return m;
        }
        m.executionMode = worker.executionMode;
        m.worldCompleted = worker.worldCompleted;
        m.analysisCompleted = worker.analysisCompleted;
        m.worldMs = worker.worldMs;
        m.ptaMs = worker.ptaMs;
        m.peakHeapBytes = worker.peakHeapBytes;
        m.peakRssBytes = worker.peakRssBytes;
        m.workerStatus = worker.status;
        m.workerExitCode = worker.exitCode;
        m.heapDumpPath = worker.heapDumpPath;
        m.gcLogPath = worker.gcLogPath;
        m.errorClass = worker.errorClass;
        m.errorMessage = worker.errorMessage;
        if (worker.phases != null) {
            m.phases.addAll(worker.phases);
        }
        if (TaieWorkerResult.STATUS_SUCCESS.equals(worker.status)) {
            m.partitionsCompleted = 1;
        } else {
            m.partitionsFailed = 1;
        }
        return m;
    }

    public void write(Path workspaceDir) {
        try {
            Path out = workspaceDir.resolve("benchmark.json");
            MAPPER.writerWithDefaultPrettyPrinter().writeValue(out.toFile(), this);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to write benchmark.json", e);
        }
    }
}
