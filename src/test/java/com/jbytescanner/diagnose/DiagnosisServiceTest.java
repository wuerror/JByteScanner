package com.jbytescanner.diagnose;

import com.jbytescanner.config.Config;
import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.config.ResourceBudget;
import com.jbytescanner.engine.RuleManager;
import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.worker.CapturedTaintFlow;
import com.jbytescanner.worker.TargetDiagnosticEvidence;
import com.jbytescanner.worker.TargetInvokeEvidence;
import com.jbytescanner.worker.TaieWorkerRequest;
import com.jbytescanner.worker.TaieWorkerResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DiagnosisServiceTest {

    private static final String SINK =
            "<java.io.File: void <init>(java.lang.String)>";
    private static final String SOURCE =
            "<com.example.Source: java.lang.String get(java.lang.String)>";

    @TempDir
    Path tempDir;

    @Test
    void workerSuccessWithoutFlowIsNotObservedButNotProvenAbsent() throws Exception {
        PreparedDiagnosisContext context = context("ws-ok");
        DiagnosisOutcome outcome = service(context, successWorker(diagnostic(), List.of()))
                .diagnose(options(null));

        assertEquals(0, outcome.exitCode());
        assertEquals(EvidenceState.YES, outcome.result().stage("invocation").state);
        assertEquals(EvidenceState.YES, outcome.result().stage("rule").state);
        assertEquals(EvidenceState.YES, outcome.result().stage("source").state);
        assertEquals(EvidenceState.YES, outcome.result().stage("entry").state);
        assertEquals(EvidenceState.YES, outcome.result().stage("reachability").state);
        assertEquals(EvidenceState.NO, outcome.result().stage("raw_flow").state);
        assertEquals(EvidenceState.UNKNOWN,
                outcome.result().stage("finding_disposition").state);
        assertEquals(EvidenceState.UNKNOWN,
                outcome.result().stage("propagation_frontier").state);
        assertEquals("not_observed_not_proven_absent",
                outcome.result().vulnerabilityConclusion);
        assertTrue(outcome.result().zeroFindingsDoesNotProveAbsence);
        assertTrue(outcome.result().suggestedNextChecks.stream()
                .anyMatch(check -> check.toLowerCase().contains("not proof")));
    }

    @Test
    void matchingFlowIsPlacedByFindingPipeline() throws Exception {
        PreparedDiagnosisContext context = context("ws-flow");
        DiagnosisOutcome outcome = service(context,
                successWorker(diagnostic(), List.of(flow())))
                .diagnose(options(null));

        assertEquals(0, outcome.exitCode());
        assertEquals(EvidenceState.YES, outcome.result().stage("raw_flow").state);
        assertEquals(EvidenceState.YES,
                outcome.result().stage("finding_disposition").state);
        assertEquals(1, outcome.result().matchedFlows.size());
        assertEquals(1, outcome.result().findingDispositions.size());
        assertEquals("low_confidence",
                outcome.result().findingDispositions.get(0).disposition);
        assertEquals("flow_observed", outcome.result().vulnerabilityConclusion);
    }


    @Test
    void unreachableInvokeDoesNotBecomeNoFlowProof() throws Exception {
        PreparedDiagnosisContext context = context("ws-unreachable");
        TargetDiagnosticEvidence diagnostic = diagnostic();
        diagnostic.targetInvokes.get(0).callerReachable = false;
        diagnostic.targetInvokes.get(0).callEdgeObserved = false;

        DiagnosisOutcome outcome = new DiagnosisService(context,
                successWorker(diagnostic, List.of()))
                .diagnose(options(null));

        assertEquals(0, outcome.exitCode());
        assertEquals(EvidenceState.NO, outcome.result().stage("reachability").state);
        assertEquals(EvidenceState.UNKNOWN, outcome.result().stage("raw_flow").state);
        assertEquals("unknown", outcome.result().vulnerabilityConclusion);
    }

    @Test
    void invocationAbsenceIsNoEvenWhenWorkerRuns() throws Exception {
        PreparedDiagnosisContext context = context("ws-no-invoke");
        String otherSink = "<java.net.URL: void <init>(java.lang.String)>";

        DiagnosisOutcome outcome = new DiagnosisService(context,
                successWorker(diagnostic(), List.of()))
                .diagnose(new DiagnosisOptions(otherSink, "0", SOURCE, "result",
                        200, 200, true));

        assertEquals(0, outcome.exitCode());
        assertEquals(EvidenceState.NO, outcome.result().stage("invocation").state);
        assertEquals(EvidenceState.NO, outcome.result().stage("rule").state);
        assertEquals(EvidenceState.UNKNOWN, outcome.result().stage("raw_flow").state);
    }


    @Test
    void dispositionOnlyReportsTheSelectedSourceInstance() throws Exception {
        PreparedDiagnosisContext context = context("ws-source-scope");
        String otherSource = "<com.example.OtherSource: java.lang.String load(java.lang.String)>";
        CapturedTaintFlow selected = flow();
        CapturedTaintFlow other = flow();
        other.sourceContainerSignature = otherSource;
        other.sourceRuleSignature = otherSource;
        other.sourceIndex = "result";
        other.sinkContainerSignature = "<com.example.Caller: void c(java.lang.String)>";
        other.sinkStmtIndex = 5;

        DiagnosisOutcome outcome = new DiagnosisService(context,
                successWorker(diagnostic(), List.of(other, selected)))
                .diagnose(options(null));

        assertEquals(0, outcome.exitCode());
        assertEquals(EvidenceState.YES, outcome.result().stage("raw_flow").state);
        assertEquals(1, outcome.result().findingDispositions.size());
        FindingDispositionEvidence placement = outcome.result().findingDispositions.get(0);
        assertEquals("<com.example.Caller: void a(java.lang.String)>",
                placement.sinkContainerSignature);
        assertEquals(0, placement.sinkStmtIndex);
        assertEquals(1, placement.sourceSignatures.size());
        assertEquals(SOURCE, placement.sourceSignatures.get(0));
    }


    @Test
    void partialConfigReadWithMissingSinkIsUnknownNotNo() throws Exception {
        PreparedDiagnosisContext context = context("ws-partial-missing");
        Path configDir = tempDir.resolve("ws-partial-missing-config");
        writeConfigShard(configDir, "000-sources.yml", """
                sources:
                  - kind: call
                    method: "<com.example.Source: java.lang.String get(java.lang.String)>"
                    index: result
                """);
        writeConfigShard(configDir, "999-broken.yml",
                "sinks:\n  - method: \"<unterminated\n");
        RuleManager manager = fixedConfigManager(context, configDir);

        DiagnosisService service = new DiagnosisService(context,
                successWorker(diagnostic(), List.of())) {
            @Override
            protected RuleManager createRuleManager(Config config) {
                return manager;
            }
        };
        DiagnosisOutcome outcome = service.diagnose(options(null));

        assertEquals(EvidenceState.YES, outcome.result().stage("source").state);
        assertEquals(EvidenceState.UNKNOWN, outcome.result().stage("rule").state);
        assertTrue(outcome.result().stage("rule").summary.contains("partial"));
        assertEquals(EvidenceState.UNKNOWN, outcome.result().stage("raw_flow").state);
    }

    @Test
    void partialConfigReadRetainsYesWhenExactSinkWasObserved() throws Exception {
        PreparedDiagnosisContext context = context("ws-partial-present");
        Path configDir = tempDir.resolve("ws-partial-present-config");
        writeConfigShard(configDir, "000-sinks.yml", """
                sinks:
                  - method: "<java.io.File: void <init>(java.lang.String)>"
                    index: 0
                """);
        writeConfigShard(configDir, "001-sources.yml", """
                sources:
                  - kind: call
                    method: "<com.example.Source: java.lang.String get(java.lang.String)>"
                    index: result
                """);
        writeConfigShard(configDir, "999-broken.yml",
                "sinks:\n  - method: \"<unterminated\n");
        RuleManager manager = fixedConfigManager(context, configDir);

        DiagnosisService service = new DiagnosisService(context,
                successWorker(diagnostic(), List.of())) {
            @Override
            protected RuleManager createRuleManager(Config config) {
                return manager;
            }
        };
        DiagnosisOutcome outcome = service.diagnose(options(null));

        assertEquals(EvidenceState.YES, outcome.result().stage("rule").state);
        assertEquals(EvidenceState.YES, outcome.result().stage("source").state);
        assertEquals(EvidenceState.NO, outcome.result().stage("raw_flow").state);
    }

    @Test
    void workerFailureLeavesDependentStagesUnknown() throws Exception {
        PreparedDiagnosisContext context = context("ws-fail");
        DiagnosisWorker failing = (request, dir) -> {
            TaieWorkerResult result = new TaieWorkerResult();
            result.status = TaieWorkerResult.STATUS_FAILED;
            result.exitCode = 1;
            result.errorClass = "java.lang.IllegalStateException";
            result.errorMessage = "synthetic failure";
            return result;
        };

        DiagnosisOutcome outcome = new DiagnosisService(context, failing)
                .diagnose(options(null));

        assertEquals(DiagnosisService.EXIT_WORKER_FAILED, outcome.exitCode());
        assertEquals(EvidenceState.YES, outcome.result().stage("invocation").state);
        assertEquals(EvidenceState.UNKNOWN, outcome.result().stage("entry").state);
        assertEquals(EvidenceState.UNKNOWN, outcome.result().stage("reachability").state);
        assertEquals(EvidenceState.UNKNOWN, outcome.result().stage("raw_flow").state);
        assertEquals("unknown", outcome.result().vulnerabilityConclusion);
    }

    @Test
    void wrongSourceIndexIsNoAndDoesNotLaunchWorker() throws Exception {
        PreparedDiagnosisContext context = context("ws-source-index");
        boolean[] launched = {false};
        DiagnosisWorker worker = (request, dir) -> {
            launched[0] = true;
            return successWorker(diagnostic(), List.of()).run(request, dir);
        };

        DiagnosisOutcome outcome = new DiagnosisService(context, worker)
                .diagnose(new DiagnosisOptions(SINK, "0", SOURCE, "1", 200, 200, true));

        assertEquals(0, outcome.exitCode());
        assertEquals(EvidenceState.NO, outcome.result().stage("source").state);
        assertEquals(EvidenceState.UNKNOWN, outcome.result().stage("raw_flow").state);
        assertTrue(!launched[0]);
    }

    @Test
    void exactRuleMustMatchSinkSignatureAndIndex() throws Exception {
        PreparedDiagnosisContext context = context("ws-rule-index");

        DiagnosisOutcome outcome = new DiagnosisService(context,
                successWorker(diagnostic(), List.of()))
                .diagnose(new DiagnosisOptions(SINK, "1", null, null, 200, 200, true));

        assertEquals(0, outcome.exitCode());
        assertEquals(EvidenceState.NO, outcome.result().stage("rule").state);
        assertEquals(EvidenceState.UNKNOWN, outcome.result().stage("raw_flow").state);
        assertTrue(outcome.result().stage("rule").details.get("configuredIndexes")
                .toString().contains("0"));
    }

    @Test
    void writesBoundedDiagnosisRecordAndLatestPointer() throws Exception {
        PreparedDiagnosisContext context = context("ws-record");
        DiagnosisOutcome outcome = new DiagnosisService(context,
                successWorker(diagnostic(), List.of()))
                .diagnose(options(null));

        Path record = Path.of(outcome.result().diagnosisRecordPath);
        assertTrue(Files.isRegularFile(record));
        assertTrue(Files.isRegularFile(context.workspace().resolve("diagnosis/latest.json")));
        assertNotNull(outcome.result().scanIdentity.workerResultPath);
        assertTrue(outcome.result().scanIdentity.artifactCount > 0);
        assertTrue(outcome.result().scanIdentity.targetAppJarCount > 0);
    }

    private void writeConfigShard(Path directory, String fileName, String content)
            throws Exception {
        Files.createDirectories(directory);
        Files.writeString(directory.resolve(fileName), content);
    }

    private RuleManager fixedConfigManager(PreparedDiagnosisContext context, Path configPath) {
        return new RuleManager(context.configManager().getConfig()) {
            @Override
            public String generateTaieConfig(List<String> entryMethodSignatures,
                                             File workspaceDir, List<String> appJars) {
                return configPath.toString();
            }
        };
    }

    private DiagnosisOptions options(String sinkIndex) {
        return new DiagnosisOptions(SINK, sinkIndex, SOURCE, "result", 200, 200, true);
    }

    private DiagnosisService service(PreparedDiagnosisContext context, DiagnosisWorker worker) {
        return new DiagnosisService(context, worker);
    }

    private PreparedDiagnosisContext context(String directory) throws Exception {
        Path workspace = tempDir.resolve(directory).resolve(".jbytescanner");
        Files.createDirectories(workspace);
        Files.writeString(workspace.resolve("rules.yaml"), """
                rules_version: 7
                config:
                  scan_packages:
                    - com.example
                sources:
                  - type: method
                    signature: "<com.example.Source: java.lang.String get(java.lang.String)>"
                    index: result
                sinks:
                  - type: method
                    vuln_type: PathTraversal
                    category: path_traversal
                    signature: "<java.io.File: void <init>(java.lang.String)>"
                    index: 0
                transfers: []
                """);
        Path classes = workspace.getParent().resolve("classes");
        TestClassFactory.writeCaller(classes);
        ConfigManager manager = new ConfigManager();
        manager.init(workspace.toFile());
        return new PreparedDiagnosisContext(
                classes.getParent().toString(),
                workspace,
                List.of(classes.toString()),
                List.of(),
                List.of(),
                manager,
                new ArrayList<ApiRoute>(),
                workspace.resolve("api.txt"),
                new ResourceBudget()
        );
    }

    private DiagnosisWorker successWorker(TargetDiagnosticEvidence diagnostic,
                                          List<CapturedTaintFlow> flows) {
        return (TaieWorkerRequest request, Path dir) -> {
            TaieWorkerResult result = new TaieWorkerResult();
            result.protocolVersion = 2;
            result.status = TaieWorkerResult.STATUS_SUCCESS;
            result.exitCode = 0;
            result.worldCompleted = true;
            result.analysisCompleted = true;
            result.taintFlows = new ArrayList<>(flows);
            result.diagnostic = diagnostic;
            result.expansionInject.put("entryCandidates", 0);
            result.expansionInject.put("entryInjected", 0);
            return result;
        };
    }

    private TargetDiagnosticEvidence diagnostic() {
        TargetDiagnosticEvidence diagnostic = new TargetDiagnosticEvidence();
        diagnostic.callGraphAvailable = true;
        diagnostic.reachableMethodCount = 1;
        TargetInvokeEvidence invoke = new TargetInvokeEvidence();
        invoke.containerSignature = "<com.example.Caller: void a(java.lang.String)>";
        invoke.stmtIndex = 0;
        invoke.lineNumber = 10;
        invoke.declaredSignature = SINK;
        invoke.callerReachable = true;
        invoke.callEdgeObserved = true;
        diagnostic.targetInvokes.add(invoke);
        return diagnostic;
    }

    private CapturedTaintFlow flow() {
        CapturedTaintFlow flow = new CapturedTaintFlow();
        flow.sourceContainerSignature = "<com.example.Source: java.lang.String get(java.lang.String)>";
        flow.sourceRuleSignature = SOURCE;
        flow.sourceKind = "CallSourcePoint";
        flow.sourceIndex = "result";
        flow.sinkRuleSignature = SINK;
        flow.sinkIndex = "0";
        flow.sinkContainerSignature = "<com.example.Caller: void a(java.lang.String)>";
        flow.sinkStmtIndex = 0;
        flow.sinkLineNumber = 10;
        flow.declaredSinkSignature = SINK;
        flow.invokeText = "invokespecial java.io.File.<init>(Ljava/lang/String;)V";
        return flow;
    }
}
