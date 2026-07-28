package com.jbytescanner.finding;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class FindingInstance {

    @JsonProperty("sourceContainerSignature")
    public String sourceContainerSignature;

    @JsonProperty("sourceRuleSignature")
    public String sourceRuleSignature;

    @JsonProperty("sourceKind")
    public String sourceKind;

    @JsonProperty("sourceIndex")
    public String sourceIndex;

    @JsonProperty("routeHttpMethod")
    public String routeHttpMethod;

    @JsonProperty("routePath")
    public String routePath;

    @JsonProperty("authBarrier")
    public double authBarrier = 1.0;

    @JsonProperty("hasRoute")
    public boolean hasRoute;

    @JsonProperty("rawFlow")
    public String rawFlow;

    public String instanceKey() {
        return String.valueOf(sourceContainerSignature) + "|"
                + String.valueOf(sourceRuleSignature) + "|"
                + String.valueOf(sourceKind) + "|"
                + String.valueOf(sourceIndex);
    }
}
