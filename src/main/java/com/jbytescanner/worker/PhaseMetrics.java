package com.jbytescanner.worker;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class PhaseMetrics {

    @JsonProperty("name")
    public String name;

    @JsonProperty("status")
    public String status;

    @JsonProperty("startedAtEpochMs")
    public long startedAtEpochMs;

    @JsonProperty("finishedAtEpochMs")
    public long finishedAtEpochMs;

    @JsonProperty("durationMs")
    public long durationMs;

    @JsonProperty("heapBeforeBytes")
    public long heapBeforeBytes;

    @JsonProperty("heapAfterBytes")
    public long heapAfterBytes;

    @JsonProperty("peakHeapBytes")
    public long peakHeapBytes;

    @JsonProperty("peakRssBytes")
    public Long peakRssBytes;

    @JsonProperty("message")
    public String message;

    public static PhaseMetrics start(String name) {
        PhaseMetrics m = new PhaseMetrics();
        m.name = name;
        m.status = "RUNNING";
        m.startedAtEpochMs = System.currentTimeMillis();
        m.heapBeforeBytes = usedHeap();
        m.peakHeapBytes = m.heapBeforeBytes;
        m.peakRssBytes = rssOrNull();
        return m;
    }

    public void finish(String status, String message) {
        this.status = status;
        this.message = message;
        this.finishedAtEpochMs = System.currentTimeMillis();
        this.durationMs = Math.max(0, finishedAtEpochMs - startedAtEpochMs);
        this.heapAfterBytes = usedHeap();
        this.peakHeapBytes = Math.max(peakHeapBytes, heapAfterBytes);
        Long rss = rssOrNull();
        if (rss != null) {
            peakRssBytes = peakRssBytes == null ? rss : Math.max(peakRssBytes, rss);
        }
    }

    public void sample() {
        long heap = usedHeap();
        peakHeapBytes = Math.max(peakHeapBytes, heap);
        Long rss = rssOrNull();
        if (rss != null) {
            peakRssBytes = peakRssBytes == null ? rss : Math.max(peakRssBytes, rss);
        }
    }

    private static long usedHeap() {
        Runtime rt = Runtime.getRuntime();
        return rt.totalMemory() - rt.freeMemory();
    }

    private static Long rssOrNull() {
        try {
            java.lang.management.OperatingSystemMXBean osBean =
                    java.lang.management.ManagementFactory.getOperatingSystemMXBean();
            if (osBean instanceof com.sun.management.OperatingSystemMXBean os) {
                long committed = os.getCommittedVirtualMemorySize();
                return committed > 0 ? committed : null;
            }
        } catch (Throwable ignored) {
            // Optional diagnostic only.
        }
        return null;
    }
}
