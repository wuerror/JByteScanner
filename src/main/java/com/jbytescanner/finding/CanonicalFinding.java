package com.jbytescanner.finding;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.jbytescanner.config.SinkRule;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class CanonicalFinding {

    @JsonProperty("ruleId")
    public String ruleId;

    @JsonProperty("sinkRuleSignature")
    public String sinkRuleSignature;

    @JsonProperty("sinkIndex")
    public String sinkIndex;

    @JsonProperty("sinkContainerSignature")
    public String sinkContainerSignature;

    @JsonProperty("sinkStmtIndex")
    public int sinkStmtIndex;

    @JsonProperty("sinkLineNumber")
    public int sinkLineNumber = -1;

    @JsonProperty("declaredSinkSignature")
    public String declaredSinkSignature;

    @JsonProperty("resolvedSinkSignature")
    public String resolvedSinkSignature;

    @JsonProperty("invokeText")
    public String invokeText;

    @JsonProperty("sinkStrength")
    public SinkStrength sinkStrength = SinkStrength.UNCLASSIFIED;

    @JsonProperty("evidenceLevel")
    public EvidenceLevel evidenceLevel = EvidenceLevel.ENDPOINT_ONLY;

    @JsonProperty("disposition")
    public FindingDisposition disposition = FindingDisposition.MAIN;

    @JsonProperty("reasonCodes")
    public List<String> reasonCodes = new ArrayList<>();

    @JsonProperty("packageProvenance")
    public String packageProvenance;

    @JsonProperty("severityScore")
    public double severityScore;

    @JsonProperty("confidenceScore")
    public double confidenceScore;

    @JsonProperty("rankScore")
    public double rankScore;

    @JsonProperty("riskLevel")
    public String riskLevel;

    @JsonProperty("sourceCount")
    public int sourceCount;

    @JsonProperty("instances")
    public List<FindingInstance> instances = new ArrayList<>();

    @JsonProperty("localFollowingSideEffects")
    public List<String> localFollowingSideEffects = new ArrayList<>();

    /** Transient: not for sidecar identity. */
    public transient SinkRule sinkRule;

    public String sinkLocationKey() {
        return String.valueOf(ruleId) + "|"
                + String.valueOf(sinkRuleSignature) + "|"
                + String.valueOf(sinkIndex) + "|"
                + String.valueOf(sinkContainerSignature) + "|"
                + sinkStmtIndex;
    }

    public String exactInstanceKey(FindingInstance inst) {
        return sinkLocationKey() + "|" + (inst != null ? inst.instanceKey() : "");
    }

    public FindingInstance representative() {
        return instances.isEmpty() ? null : instances.get(0);
    }

    public void addReason(String code) {
        if (code == null || code.isBlank()) {
            return;
        }
        if (reasonCodes == null) {
            reasonCodes = new ArrayList<>();
        }
        if (!reasonCodes.contains(code)) {
            reasonCodes.add(code);
        }
    }

    public void mergeInstance(FindingInstance inst) {
        if (inst == null) {
            return;
        }
        if (instances == null) {
            instances = new ArrayList<>();
        }
        Set<String> seen = new LinkedHashSet<>();
        for (FindingInstance existing : instances) {
            seen.add(existing.instanceKey());
        }
        if (seen.add(inst.instanceKey())) {
            instances.add(inst);
        }
        sourceCount = instances.size();
    }
}
