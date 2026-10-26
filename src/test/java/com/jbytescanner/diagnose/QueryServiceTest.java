package com.jbytescanner.diagnose;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jbytescanner.finding.CanonicalFinding;
import com.jbytescanner.finding.FindingDisposition;
import com.jbytescanner.finding.FindingInstance;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QueryServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SINK =
            "<java.io.File: void <init>(java.lang.String)>";

    @TempDir
    Path tempDir;

    @Test
    void missingSidecarsAreUnknownAndRequestTargetedDiagnosis() {
        QueryOutcome outcome = new QueryService(tempDir).query(
                new QueryOptions("findings", SINK, null, null, null, 100));

        assertEquals(QueryService.EXIT_UNAVAILABLE, outcome.exitCode());
        assertEquals(EvidenceState.UNKNOWN, outcome.result().evidenceState);
        assertTrue(outcome.result().requiresTargetedDiagnosis);
        assertEquals("unknown", outcome.result().vulnerabilityConclusion);
    }

    @Test
    void emptySidecarIsNoFindingNotNoVulnerability() throws Exception {
        Files.writeString(tempDir.resolve("findings-main.jsonl"), "");

        QueryOutcome outcome = new QueryService(tempDir).query(
                new QueryOptions("findings", SINK, null, null, null, 100));

        assertEquals(QueryService.EXIT_OK, outcome.exitCode());
        assertEquals(EvidenceState.NO, outcome.result().evidenceState);
        assertTrue(outcome.result().requiresTargetedDiagnosis);
        assertTrue(outcome.result().zeroFindingsDoesNotProveAbsence);
        assertEquals("unknown", outcome.result().vulnerabilityConclusion);
    }

    @Test
    void findsExactSinkAndSourceWithoutWorkerOrFingerprints() throws Exception {
        Files.writeString(tempDir.resolve("findings-main.jsonl"),
                MAPPER.writeValueAsString(finding()) + "\n");

        QueryOutcome outcome = new QueryService(tempDir).query(
                new QueryOptions("finding", SINK, "0", null, null, 100));

        assertEquals(QueryService.EXIT_OK, outcome.exitCode());
        assertEquals(EvidenceState.YES, outcome.result().evidenceState);
        assertEquals(1, outcome.result().findings.size());
        assertEquals("finding_observed", outcome.result().vulnerabilityConclusion);
        assertNull(outcome.result().worker);
        assertTrue(outcome.result().notes.stream()
                .anyMatch(note -> note.contains("worker-result.json is missing")));
    }

    @Test
    void findingQueryReturnsRecordsEvenWhenWorkerFailed() throws Exception {
        Files.writeString(tempDir.resolve("findings-main.jsonl"),
                MAPPER.writeValueAsString(finding()) + "\n");
        Path workerDir = tempDir.resolve("worker/single");
        Files.createDirectories(workerDir);
        Files.writeString(workerDir.resolve("worker-result.json"),
                MAPPER.writeValueAsString(Map.of("status", "FAILED", "exitCode", 1)));

        QueryOutcome outcome = new QueryService(tempDir).query(
                new QueryOptions("finding", SINK, "0", null, null, 100));

        assertEquals(QueryService.EXIT_OK, outcome.exitCode());
        assertEquals(EvidenceState.YES, outcome.result().evidenceState);
        assertEquals("FAILED", outcome.result().worker.get("status"));
        assertTrue(outcome.result().notes.stream()
                .anyMatch(note -> note.contains("finding sidecars")));
    }

    @Test
    void successfulScanStatusDoesNotRequireFingerprints() throws Exception {
        Path workerDir = tempDir.resolve("worker/single");
        Files.createDirectories(workerDir);
        Files.writeString(workerDir.resolve("worker-result.json"),
                MAPPER.writeValueAsString(Map.of(
                        "status", "SUCCESS",
                        "exitCode", 0,
                        "worldCompleted", true,
                        "analysisCompleted", true,
                        "totalMs", 100)));

        QueryOutcome outcome = new QueryService(tempDir).query(
                new QueryOptions("scan-status", null, null, null, null, 100));

        assertEquals(QueryService.EXIT_OK, outcome.exitCode());
        assertEquals(EvidenceState.YES, outcome.result().evidenceState);
        assertEquals("scan_completed", outcome.result().vulnerabilityConclusion);
        assertEquals("SUCCESS", outcome.result().worker.get("status"));
        assertFalse(outcome.result().notes.stream()
                .anyMatch(note -> note.toLowerCase().contains("fingerprint")
                        || note.toLowerCase().contains("stale")));
    }

    @Test
    void failedScanStatusReportsWorkerFailure() throws Exception {
        Path workerDir = tempDir.resolve("worker/single");
        Files.createDirectories(workerDir);
        Files.writeString(workerDir.resolve("worker-result.json"),
                MAPPER.writeValueAsString(Map.of(
                        "status", "OOM",
                        "exitCode", 1,
                        "errorClass", "java.lang.OutOfMemoryError")));

        QueryOutcome outcome = new QueryService(tempDir).query(
                new QueryOptions("scan-status", null, null, null, null, 100));

        assertEquals(QueryService.EXIT_WORKER_FAILED, outcome.exitCode());
        assertEquals(EvidenceState.UNKNOWN, outcome.result().evidenceState);
        assertEquals("unknown", outcome.result().vulnerabilityConclusion);
        assertEquals("OOM", outcome.result().worker.get("status"));
    }

    @Test
    void missingWorkerStatusIsUnavailable() {
        QueryOutcome outcome = new QueryService(tempDir).query(
                new QueryOptions("scan-status", null, null, null, null, 100));

        assertEquals(QueryService.EXIT_UNAVAILABLE, outcome.exitCode());
        assertEquals(EvidenceState.UNKNOWN, outcome.result().evidenceState);
    }

    private CanonicalFinding finding() {
        CanonicalFinding finding = new CanonicalFinding();
        finding.ruleId = "PathTraversal";
        finding.sinkRuleSignature = SINK;
        finding.sinkIndex = "0";
        finding.sinkContainerSignature = "<com.example.Caller: void a(java.lang.String)>";
        finding.sinkStmtIndex = 4;
        finding.disposition = FindingDisposition.MAIN;
        finding.sourceCount = 1;
        FindingInstance instance = new FindingInstance();
        instance.sourceContainerSignature =
                "<com.example.Source: java.lang.String get(java.lang.String)>";
        instance.sourceRuleSignature = instance.sourceContainerSignature;
        instance.sourceIndex = "result";
        finding.instances.add(instance);
        return finding;
    }
}
