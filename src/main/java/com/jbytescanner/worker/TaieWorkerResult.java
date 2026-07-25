package com.jbytescanner.worker;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class TaieWorkerResult {

    public static final String STATUS_SUCCESS = "SUCCESS";
    public static final String STATUS_FAILED = "FAILED";
    public static final String STATUS_OOM = "OOM";
    public static final String STATUS_TIMEOUT = "TIMEOUT";
    public static final String STATUS_CANCELLED = "CANCELLED";

    @JsonProperty("status")
    public String status;

    @JsonProperty("batchId")
    public String batchId;

    @JsonProperty("executionMode")
    public String executionMode;

    @JsonProperty("exitCode")
    public int exitCode;

    @JsonProperty("errorClass")
    public String errorClass;

    @JsonProperty("errorMessage")
    public String errorMessage;

    @JsonProperty("errorStackTrace")
    public String errorStackTrace;

    @JsonProperty("heapDumpPath")
    public String heapDumpPath;

    @JsonProperty("gcLogPath")
    public String gcLogPath;

    @JsonProperty("worldCompleted")
    public boolean worldCompleted;

    @JsonProperty("analysisCompleted")
    public boolean analysisCompleted;

    @JsonProperty("applicationClassCount")
    public long applicationClassCount;

    @JsonProperty("phases")
    public List<PhaseMetrics> phases = new ArrayList<>();

    @JsonProperty("peakHeapBytes")
    public long peakHeapBytes;

    @JsonProperty("peakRssBytes")
    public Long peakRssBytes;

    @JsonProperty("worldMs")
    public long worldMs;

    @JsonProperty("ptaMs")
    public long ptaMs;

    @JsonProperty("totalMs")
    public long totalMs;

    @JsonProperty("taiELogPath")
    public String taiELogPath;

    public PhaseMetrics phase(String name) {
        for (PhaseMetrics p : phases) {
            if (name.equals(p.name)) {
                return p;
            }
        }
        return null;
    }
}
