package com.jbytescanner.worker;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class TargetInvokeEvidence {

    @JsonProperty("containerSignature")
    public String containerSignature;

    @JsonProperty("stmtIndex")
    public int stmtIndex;

    @JsonProperty("lineNumber")
    public int lineNumber = -1;

    @JsonProperty("invokeText")
    public String invokeText;

    @JsonProperty("declaredSignature")
    public String declaredSignature;

    @JsonProperty("resolvedSignature")
    public String resolvedSignature;

    @JsonProperty("callerReachable")
    public boolean callerReachable;

    @JsonProperty("callEdgeObserved")
    public boolean callEdgeObserved;

    @JsonProperty("resolvedCallees")
    public List<String> resolvedCallees = new ArrayList<>();

    @JsonProperty("calleeReachable")
    public boolean calleeReachable;
}
