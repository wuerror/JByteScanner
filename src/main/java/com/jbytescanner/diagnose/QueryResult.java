package com.jbytescanner.diagnose;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.jbytescanner.finding.CanonicalFinding;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class QueryResult {

    public static final String SCHEMA_VERSION = "jbs-query/v1";

    @JsonProperty("schemaVersion")
    public String schemaVersion = SCHEMA_VERSION;

    @JsonProperty("generatedAt")
    public String generatedAt;

    @JsonProperty("command")
    public String command = "query";

    @JsonProperty("query")
    public String query;

    @JsonProperty("workspace")
    public String workspace;

    @JsonProperty("evidenceState")
    public EvidenceState evidenceState;

    @JsonProperty("artifacts")
    public List<Map<String, Object>> artifacts = new ArrayList<>();

    @JsonProperty("findings")
    public List<CanonicalFinding> findings = new ArrayList<>();

    @JsonProperty("counts")
    public Map<String, Object> counts = new LinkedHashMap<>();

    @JsonProperty("worker")
    public Map<String, Object> worker;

    @JsonProperty("zeroFindingsDoesNotProveAbsence")
    public boolean zeroFindingsDoesNotProveAbsence = true;

    @JsonProperty("requiresTargetedDiagnosis")
    public boolean requiresTargetedDiagnosis;

    @JsonProperty("vulnerabilityConclusion")
    public String vulnerabilityConclusion;

    @JsonProperty("notes")
    public List<String> notes = new ArrayList<>();

    @JsonProperty("error")
    public String error;
}
