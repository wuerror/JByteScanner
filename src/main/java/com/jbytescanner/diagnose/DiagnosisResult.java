package com.jbytescanner.diagnose;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.jbytescanner.worker.CapturedTaintFlow;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class DiagnosisResult {

    public static final String SCHEMA_VERSION = "jbs-diagnosis/v1";

    @JsonProperty("schemaVersion")
    public String schemaVersion = SCHEMA_VERSION;

    @JsonProperty("generatedAt")
    public String generatedAt;

    @JsonProperty("command")
    public String command = "diagnose";

    @JsonProperty("target")
    public DiagnosisTarget target;

    @JsonProperty("scanIdentity")
    public DiagnosisScanIdentity scanIdentity;

    @JsonProperty("worker")
    public DiagnosisWorkerSummary worker;

    @JsonProperty("stages")
    public List<DiagnosisStage> stages = new ArrayList<>();

    @JsonProperty("matchedFlows")
    public List<CapturedTaintFlow> matchedFlows = new ArrayList<>();

    @JsonProperty("findingDispositions")
    public List<FindingDispositionEvidence> findingDispositions = new ArrayList<>();

    @JsonProperty("limits")
    public Map<String, Object> limits = new LinkedHashMap<>();

    @JsonProperty("suggestedNextChecks")
    public List<String> suggestedNextChecks = new ArrayList<>();

    @JsonProperty("vulnerabilityConclusion")
    public String vulnerabilityConclusion;

    @JsonProperty("zeroFindingsDoesNotProveAbsence")
    public boolean zeroFindingsDoesNotProveAbsence = true;

    @JsonProperty("summary")
    public String summary;

    @JsonProperty("diagnosisRecordPath")
    public String diagnosisRecordPath;

    @JsonProperty("error")
    public String error;

    public DiagnosisStage stage(String id) {
        for (DiagnosisStage stage : stages) {
            if (id.equals(stage.id)) {
                return stage;
            }
        }
        return null;
    }
}
