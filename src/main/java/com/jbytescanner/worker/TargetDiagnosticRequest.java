package com.jbytescanner.worker;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Targeted, bounded worker-side evidence request. Only set by {@code diagnose};
 * ordinary scan requests leave this null and pay no diagnostic cost.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TargetDiagnosticRequest {

    @JsonProperty("sinkSignature")
    public String sinkSignature;

    @JsonProperty("sinkIndex")
    public String sinkIndex;

    @JsonProperty("sourceSignature")
    public String sourceSignature;

    @JsonProperty("sourceIndex")
    public String sourceIndex;

    @JsonProperty("entrySignaturesToCheck")
    public List<String> entrySignaturesToCheck = new ArrayList<>();

    @JsonProperty("maxTargetInvokes")
    public int maxTargetInvokes = 200;

    @JsonProperty("maxReachableMethods")
    public int maxReachableMethods = 2_000_000;

    @JsonProperty("maxApplicationMethods")
    public int maxApplicationMethods = 2_000_000;

    @JsonProperty("maxCalleesPerInvoke")
    public int maxCalleesPerInvoke = 64;
}
