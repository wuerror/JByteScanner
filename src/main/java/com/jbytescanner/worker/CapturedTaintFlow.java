package com.jbytescanner.worker;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * JSON-safe snapshot of one Tai-e taint flow.
 *
 * <p>The Tai-e object graph contains package-private IR objects and must not be
 * serialized directly. The worker creates this snapshot while its Tai-e World
 * is still alive and sends it to the host via {@code worker-result.json}.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CapturedTaintFlow {

    @JsonProperty("sourceContainerSignature")
    public String sourceContainerSignature;

    @JsonProperty("sourceRuleSignature")
    public String sourceRuleSignature;

    @JsonProperty("sourceKind")
    public String sourceKind;

    @JsonProperty("sourceIndex")
    public String sourceIndex;

    /** Exact configured sink method carried by Tai-e's Sink object. */
    @JsonProperty("sinkRuleSignature")
    public String sinkRuleSignature;

    @JsonProperty("sinkIndex")
    public String sinkIndex;

    @JsonProperty("sinkContainerSignature")
    public String sinkContainerSignature;

    @JsonProperty("declaredSinkSignature")
    public String declaredSinkSignature;

    @JsonProperty("resolvedSinkSignature")
    public String resolvedSinkSignature;

    @JsonProperty("sinkStmtIndex")
    public int sinkStmtIndex;

    @JsonProperty("sinkLineNumber")
    public int sinkLineNumber;

    @JsonProperty("invokeText")
    public String invokeText;

    /** Diagnostic only; never used to infer the vulnerability type. */
    @JsonProperty("rawFlow")
    public String rawFlow;
}
