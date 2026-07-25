package com.jbytescanner.worker;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Inputs prepared by the main process and consumed by {@link TaieWorkerMain}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TaieWorkerRequest {

    @JsonProperty("workspaceDir")
    public String workspaceDir;

    @JsonProperty("outputDir")
    public String outputDir;

    @JsonProperty("targetAppJars")
    public List<String> targetAppJars = new ArrayList<>();

    @JsonProperty("classPathJars")
    public List<String> classPathJars = new ArrayList<>();

    @JsonProperty("entrySignatures")
    public List<String> entrySignatures = new ArrayList<>();

    @JsonProperty("supplementalEntrySignatures")
    public List<String> supplementalEntrySignatures = new ArrayList<>();

    @JsonProperty("taintConfigPath")
    public String taintConfigPath;

    @JsonProperty("springAnalysis")
    public boolean springAnalysis = true;

    @JsonProperty("springServiceEntryFallback")
    public boolean springServiceEntryFallback;

    @JsonProperty("taintCallSiteMode")
    public boolean taintCallSiteMode = true;

    @JsonProperty("batchId")
    public String batchId = "single";

    @JsonProperty("executionMode")
    public String executionMode = "single";
}
