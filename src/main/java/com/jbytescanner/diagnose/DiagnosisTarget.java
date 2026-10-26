package com.jbytescanner.diagnose;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class DiagnosisTarget {

    @JsonProperty("path")
    public String path;

    @JsonProperty("workspace")
    public String workspace;

    @JsonProperty("sinkSignature")
    public String sinkSignature;

    @JsonProperty("sinkIndex")
    public String sinkIndex;

    @JsonProperty("sourceSignature")
    public String sourceSignature;

    @JsonProperty("sourceIndex")
    public String sourceIndex;
}
