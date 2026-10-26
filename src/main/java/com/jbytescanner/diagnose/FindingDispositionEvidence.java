package com.jbytescanner.diagnose;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class FindingDispositionEvidence {

    @JsonProperty("findingId")
    public String findingId;

    @JsonProperty("disposition")
    public String disposition;

    @JsonProperty("ruleId")
    public String ruleId;

    @JsonProperty("sinkRuleSignature")
    public String sinkRuleSignature;

    @JsonProperty("sinkIndex")
    public String sinkIndex;

    @JsonProperty("sinkContainerSignature")
    public String sinkContainerSignature;

    @JsonProperty("sinkStmtIndex")
    public Integer sinkStmtIndex;

    @JsonProperty("sourceCount")
    public Integer sourceCount;

    @JsonProperty("reasonCodes")
    public List<String> reasonCodes = new ArrayList<>();

    @JsonProperty("sourceSignatures")
    public List<String> sourceSignatures = new ArrayList<>();
}
