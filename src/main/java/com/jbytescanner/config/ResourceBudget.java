package com.jbytescanner.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * Resource budget for Tai-e semantic analysis (World / PTA / TFG).
 *
 * <p>P0.3: analysis runs in an isolated worker JVM with explicit heap, heap-dump,
 * GC logging and phase metrics. Main process keeps preparing inputs and collecting
 * results so an OOM in the worker cannot corrupt the host scan state.
 */
@Data
public class ResourceBudget {

    /** Run Tai-e World/PTA in a child JVM (recommended for production scans). */
    @JsonProperty("worker_enabled")
    private boolean workerEnabled = true;

    /**
     * Allow falling back to in-process analysis when the worker cannot be launched.
     * Default false so a spawn/CP failure cannot silently reintroduce host-JVM OOM.
     * Enable only for IDE/unit-test convenience.
     */
    @JsonProperty("allow_in_process_fallback")
    private boolean allowInProcessFallback = false;

    /** Worker -Xmx in megabytes. */
    @JsonProperty("max_heap_mb")
    private int maxHeapMb = 8192;

    /** Worker -Xms in megabytes. 0 means omit -Xms. */
    @JsonProperty("min_heap_mb")
    private int minHeapMb = 0;

    /** Soft wall-clock timeout for a single worker batch (minutes). 0 = no timeout. */
    @JsonProperty("timeout_minutes")
    private int timeoutMinutes = 0;

    /** Write GC log under the workspace worker directory. */
    @JsonProperty("gc_log")
    private boolean gcLog = true;

    /** Enable -XX:+HeapDumpOnOutOfMemoryError into the workspace. */
    @JsonProperty("heap_dump_on_oom")
    private boolean heapDumpOnOom = true;

    /**
     * Recommended execution mode after preflight. Values: {@code single},
     * {@code partition}. Partition scheduling itself lands in a later step;
     * the budget object already carries the decision field.
     */
    @JsonProperty("execution_mode")
    private String executionMode = "single";

    public int effectiveMinHeapMb() {
        if (minHeapMb <= 0) {
            return 0;
        }
        return Math.min(minHeapMb, Math.max(1, maxHeapMb));
    }
}
