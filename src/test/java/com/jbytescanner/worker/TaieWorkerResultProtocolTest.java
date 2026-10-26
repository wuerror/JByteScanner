package com.jbytescanner.worker;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
    void targetedDiagnosticEvidenceSurvivesWorkerJsonRoundTrip() throws Exception {
        TargetDiagnosticEvidence diagnostic = new TargetDiagnosticEvidence();
        diagnostic.callGraphAvailable = true;
        diagnostic.reachableMethodCount = 12;
        EntryCheckEvidence entry = new EntryCheckEvidence();
        entry.signature = "<example.Controller: void run(java.lang.String)>";
        entry.status = "INJECTED";
        diagnostic.entryChecks.add(entry);
        TargetInvokeEvidence invoke = new TargetInvokeEvidence();
        invoke.containerSignature = "<example.Controller: void run(java.lang.String)>";
        invoke.stmtIndex = 7;
        invoke.declaredSignature =
                "<java.io.File: void <init>(java.lang.String)>";
        invoke.callerReachable = true;
        diagnostic.targetInvokes.add(invoke);

        TaieWorkerResult result = new TaieWorkerResult();
        result.status = TaieWorkerResult.STATUS_SUCCESS;
        result.diagnostic = diagnostic;

        TaieWorkerResult restored = mapper.readValue(
                mapper.writeValueAsBytes(result), TaieWorkerResult.class);

        assertNotNull(restored.diagnostic);
        assertEquals(1, restored.diagnostic.entryChecks.size());
        assertEquals("INJECTED", restored.diagnostic.entryChecks.get(0).status);
        assertEquals(1, restored.diagnostic.targetInvokes.size());
        assertEquals(7, restored.diagnostic.targetInvokes.get(0).stmtIndex);
        assertEquals(true, restored.diagnostic.targetInvokes.get(0).callerReachable);
    }

    @Test
    void missingDiagnosticTargetIsAbsentForOrdinaryScanRequests() throws Exception {
        TaieWorkerRequest request = mapper.readValue(
                "{\"batchId\":\"single\"}", TaieWorkerRequest.class);
        assertEquals(null, request.diagnosticTarget);

        TaieWorkerResult result = mapper.readValue(
                "{\"status\":\"SUCCESS\"}", TaieWorkerResult.class);
        assertEquals(null, result.diagnostic);
    }

    @Test
    void missingProtocolVersionDeserializesAsLegacyV1() throws Exception {
        TaieWorkerResult restored = mapper.readValue(
                "{\"status\":\"SUCCESS\"}", TaieWorkerResult.class);

        assertEquals(1, restored.protocolVersion);
        assertEquals(0, restored.taintFlows.size());
    }
}
