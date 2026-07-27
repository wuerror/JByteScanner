package com.jbytescanner.worker;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TaieWorkerResultProtocolTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void structuredFlowSurvivesWorkerJsonRoundTrip() throws Exception {
        CapturedTaintFlow flow = new CapturedTaintFlow();
        flow.sourceContainerSignature =
                "<example.Controller: void run(java.lang.String)>";
        flow.sinkRuleSignature =
                "<org.slf4j.Logger: void info(java.lang.String)>";
        flow.declaredSinkSignature =
                "<org.slf4j.Logger: void info(java.lang.String)>";
        flow.sinkStmtIndex = 8;
        flow.sinkLineNumber = 239;
        flow.invokeText = "invokeinterface %v8.info(%v13)";

        TaieWorkerResult result = new TaieWorkerResult();
        result.protocolVersion = 2;
        result.taintFlows.add(flow);

        TaieWorkerResult restored = mapper.readValue(
                mapper.writeValueAsBytes(result), TaieWorkerResult.class);

        assertEquals(2, restored.protocolVersion);
        assertEquals(1, restored.taintFlows.size());
        assertEquals(flow.sinkRuleSignature,
                restored.taintFlows.get(0).sinkRuleSignature);
        assertEquals(flow.invokeText,
                restored.taintFlows.get(0).invokeText);
    }

    @Test
    void missingProtocolVersionDeserializesAsLegacyV1() throws Exception {
        TaieWorkerResult restored = mapper.readValue(
                "{\"status\":\"SUCCESS\"}", TaieWorkerResult.class);

        assertEquals(1, restored.protocolVersion);
        assertEquals(0, restored.taintFlows.size());
    }
}
