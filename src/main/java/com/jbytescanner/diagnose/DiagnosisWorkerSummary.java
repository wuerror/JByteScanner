package com.jbytescanner.diagnose;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class DiagnosisWorkerSummary {

    @JsonProperty("requested")
    public boolean requested;

    @JsonProperty("status")
    public String status;

    @JsonProperty("exitCode")
    public Integer exitCode;

    @JsonProperty("worldCompleted")
    public Boolean worldCompleted;

    @JsonProperty("analysisCompleted")
    public Boolean analysisCompleted;

    @JsonProperty("totalMs")
    public Long totalMs;

    @JsonProperty("worldMs")
    public Long worldMs;

    @JsonProperty("ptaMs")
    public Long ptaMs;

    @JsonProperty("errorClass")
    public String errorClass;

    @JsonProperty("errorMessage")
    public String errorMessage;

    @JsonProperty("resultPath")
    public String resultPath;

    @JsonProperty("diagnosticAvailable")
    public Boolean diagnosticAvailable;
}
