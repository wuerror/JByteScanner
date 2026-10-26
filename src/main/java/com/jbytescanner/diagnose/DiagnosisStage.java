package com.jbytescanner.diagnose;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class DiagnosisStage {

    public static final String BYTECODE = "bytecode";
    public static final String CONFIG = "configuration";
    public static final String ENTRY = "entry";
    public static final String REACHABILITY = "reachability";
    public static final String TAINT = "taint";
    public static final String FINDING_DISPOSITION = "finding_disposition";
    public static final String INFERENCE = "inference";
    public static final String ARTIFACT = "artifact";

    @JsonProperty("id")
    public String id;

    @JsonProperty("state")
    public EvidenceState state;

    @JsonProperty("summary")
    public String summary;

    @JsonProperty("evidenceLevel")
    public String evidenceLevel;

    @JsonProperty("evidence")
    public List<Map<String, Object>> evidence = new ArrayList<>();

    @JsonProperty("details")
    public Map<String, Object> details = new LinkedHashMap<>();

    public static DiagnosisStage of(String id, EvidenceState state, String summary,
                                    String evidenceLevel) {
        DiagnosisStage stage = new DiagnosisStage();
        stage.id = id;
        stage.state = state;
        stage.summary = summary;
        stage.evidenceLevel = evidenceLevel;
        return stage;
    }

    public DiagnosisStage detail(String key, Object value) {
        if (key != null) {
            details.put(key, value);
        }
        return this;
    }

    public DiagnosisStage evidence(Map<String, Object> item) {
        if (item != null) {
            evidence.add(item);
        }
        return this;
    }

    public DiagnosisStage reference(Object... keyValues) {
        Map<String, Object> item = new LinkedHashMap<>();
        for (int i = 0; i + 1 < keyValues.length; i += 2) {
            item.put(String.valueOf(keyValues[i]), keyValues[i + 1]);
        }
        evidence.add(item);
        return this;
    }

    public boolean isYes() {
        return state == EvidenceState.YES;
    }
}
