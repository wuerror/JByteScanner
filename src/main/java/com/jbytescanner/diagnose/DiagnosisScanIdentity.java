package com.jbytescanner.diagnose;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class DiagnosisScanIdentity {

    @JsonProperty("artifactCount")
    public int artifactCount;

    @JsonProperty("targetAppJarCount")
    public int targetAppJarCount;

    @JsonProperty("classPathJarCount")
    public int classPathJarCount;

    @JsonProperty("taintConfigPath")
    public String taintConfigPath;

    @JsonProperty("workerResultPath")
    public String workerResultPath;
}
