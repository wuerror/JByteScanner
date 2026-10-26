package com.jbytescanner.worker;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bounded endpoint/call-graph evidence for one target sink. Intermediate taint
 * propagation is intentionally not represented: Tai-e 0.5.4 exposes completed
 * taint flows, not the taint frontier inside a method.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TargetDiagnosticEvidence {

    @JsonProperty("callGraphAvailable")
    public boolean callGraphAvailable;

    @JsonProperty("reachableMethodCount")
    public long reachableMethodCount;

    @JsonProperty("reachableScanTruncated")
    public boolean reachableScanTruncated;

    @JsonProperty("applicationMethodsScanned")
    public long applicationMethodsScanned;

    @JsonProperty("irScanTruncated")
    public boolean irScanTruncated;

    @JsonProperty("entryChecks")
    public List<EntryCheckEvidence> entryChecks = new ArrayList<>();

    @JsonProperty("targetInvokes")
    public List<TargetInvokeEvidence> targetInvokes = new ArrayList<>();

    @JsonProperty("limits")
    public Map<String, Object> limits = new LinkedHashMap<>();

    @JsonProperty("notes")
    public List<String> notes = new ArrayList<>();
}
