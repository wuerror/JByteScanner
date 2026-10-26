package com.jbytescanner.diagnose;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.jbytescanner.config.Config;
import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.config.ResourceBudget;
import com.jbytescanner.config.ScanConfig;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.engine.CanonicalIdentity;
import com.jbytescanner.engine.JBSScanEntryPointPlugin;
import com.jbytescanner.engine.RuleManager;
import com.jbytescanner.finding.CanonicalFinding;
import com.jbytescanner.finding.FindingInstance;
import com.jbytescanner.finding.FindingPipeline;
import com.jbytescanner.finding.PipelineResult;
import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.worker.CapturedTaintFlow;
import com.jbytescanner.worker.EntryCheckEvidence;
import com.jbytescanner.worker.TaieWorkerRequest;
import com.jbytescanner.worker.TaieWorkerResult;
import com.jbytescanner.worker.TargetDiagnosticEvidence;
import com.jbytescanner.worker.TargetDiagnosticRequest;
import com.jbytescanner.worker.TargetInvokeEvidence;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Orchestrates the six-stage targeted diagnosis. Deterministic host checks run
 * before Tai-e; worker-dependent stages are {@code unknown} when the worker
 * fails, times out, or leaves incomplete evidence.
 */
public class DiagnosisService {

    public static final int EXIT_OK = 0;
    public static final int EXIT_WORKER_FAILED = 4;

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL);

    private final PreparedDiagnosisContext context;
    private final DiagnosisWorker worker;

    public DiagnosisService(PreparedDiagnosisContext context, DiagnosisWorker worker) {
        this.context = context;
        this.worker = worker;
    }

    public DiagnosisOutcome diagnose(DiagnosisOptions options) {
        TaiEMethodSignature sink = TaiEMethodSignature.parse(options.sinkSignature());
        TaiEMethodSignature source = options.sourceSignature() == null
                ? null : TaiEMethodSignature.parse(options.sourceSignature());
        String requestedSinkIndex = TaiEMethodSignature.normalizeIndex(options.sinkIndex());
        String requestedSourceIndex = TaiEMethodSignature.normalizeIndex(options.sourceIndex());

        DiagnosisResult result = new DiagnosisResult();
        result.generatedAt = Instant.now().toString();
        result.target = new DiagnosisTarget();
        result.target.path = context.targetPath();
        result.target.workspace = context.workspace().toString();
        result.target.sinkSignature = sink.canonical();
        result.target.sinkIndex = requestedSinkIndex;
        result.target.sourceSignature = source == null ? null : source.canonical();
        result.target.sourceIndex = requestedSourceIndex;
        result.scanIdentity = new DiagnosisScanIdentity();
        result.scanIdentity.artifactCount = context.allArtifacts().size();
        result.scanIdentity.targetAppJarCount = context.targetAppJars().size();
        result.scanIdentity.classPathJarCount =
                context.libJars().size() + context.depAppJars().size();
        result.worker = new DiagnosisWorkerSummary();

        // 1. Exact bytecode invoke.
        DiagnosisStage invocation = checkInvocation(sink, options.maxCallers());
        result.stages.add(invocation);

        // 2. Sink rule / index emission and source presence.
        Config config = context.configManager() != null
                ? context.configManager().getConfig() : null;
        SinkRule sinkRule = findSinkRule(config, sink);
        List<String> entrySignatures = entrySignatures(context.routes());
        RuleManager ruleManager = createRuleManager(config != null ? config : new Config());
        String taintConfigPath = null;
        TaintConfigInspector.EmittedConfig emitted = null;
        String generationError = null;
        try {
            taintConfigPath = ruleManager.generateTaieConfig(entrySignatures,
                    context.workspace().toFile(), context.allAppJars());
            if (taintConfigPath != null) {
                emitted = TaintConfigInspector.read(Path.of(taintConfigPath));
                result.scanIdentity.taintConfigPath = taintConfigPath;
            } else {
                generationError = "RuleManager returned no taint config";
            }
        } catch (Exception e) {
            generationError = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        if (emitted == null) {
            emitted = TaintConfigInspector.read(null);
        }
        DiagnosisStage rule = checkRule(sink, requestedSinkIndex, sinkRule, emitted,
                generationError, taintConfigPath);
        result.stages.add(rule);

        DiagnosisStage sourceStage = checkSource(source, requestedSourceIndex, emitted,
                generationError, entrySignatures);
        result.stages.add(sourceStage);

        boolean setupFailed = generationError != null && rule.isYes();
        boolean ruleOk = rule.isYes();
        boolean sourceOk = sourceStage.isYes();

        if (!ruleOk || !sourceOk || !options.runWorker()) {
            addNotRunStages(result, ruleOk, sourceOk, options.runWorker(), generationError,
                    invocation);
            result.worker.requested = options.runWorker();
            result.worker.status = options.runWorker() ? "NOT_RUN" : "NOT_REQUESTED";
            result.summary = "Targeted analysis was not launched because a prerequisite stage failed.";
            if (setupFailed) {
                result.error = generationError;
            }
            result.vulnerabilityConclusion = "unknown";
            addSuggestedChecks(result, sink, source);
            return writeAndReturn(result, null, setupFailed ? EXIT_WORKER_FAILED : EXIT_OK);
        }

        // 3. Targeted Tai-e worker.
        TaieWorkerResult workerResult;
        Path workerDir = context.workspace()
                .resolve("diagnosis")
                .resolve(batchId(sink, source, requestedSinkIndex, requestedSourceIndex));
        TaieWorkerRequest request = buildWorkerRequest(sink, source, requestedSinkIndex,
                requestedSourceIndex, entrySignatures, taintConfigPath,
                options.maxTargetInvokes(), workerDir);
        result.worker.requested = true;
        result.worker.resultPath = workerDir.resolve("worker-result.json").toString();
        result.scanIdentity.workerResultPath = result.worker.resultPath;
        try {
            Files.createDirectories(workerDir);
            workerResult = worker.run(request, workerDir);
        } catch (Throwable t) {
            workerResult = new TaieWorkerResult();
            workerResult.status = TaieWorkerResult.STATUS_FAILED;
            workerResult.exitCode = 1;
            workerResult.errorClass = t.getClass().getName();
            workerResult.errorMessage = t.getMessage();
        }
        fillWorkerSummary(result.worker, workerResult);
        boolean workerOk = workerResult != null
                && TaieWorkerResult.STATUS_SUCCESS.equals(workerResult.status);

        if (!workerOk) {
            addWorkerFailureStages(result, workerResult);
            result.vulnerabilityConclusion = "unknown";
            result.summary = "Tai-e worker did not complete; reachability, flow, and disposition "
                    + "evidence are unknown.";
            addSuggestedChecks(result, sink, source);
            return writeAndReturn(result, workerDir, EXIT_WORKER_FAILED);
        }

        DiagnosisStage entry = checkEntry(source, sourceStage, emitted, workerResult);
        DiagnosisStage reachability = checkReachability(invocation, workerResult);

        List<CapturedTaintFlow> matched = matchedFlows(workerResult, sink, source,
                requestedSinkIndex, requestedSourceIndex);
        result.stages.add(entry);
        result.stages.add(reachability);
        result.matchedFlows.addAll(matched);
        DiagnosisStage rawFlow = checkRawFlow(matched, workerResult, rule, sourceStage, entry,
                reachability);
        result.stages.add(rawFlow);

        DiagnosisStage disposition = checkDisposition(matched, workerResult, ruleManager, sink,
                requestedSinkIndex, result);
        result.stages.add(disposition);

        DiagnosisStage propagation = checkPropagation(rawFlow, workerResult, rule, sourceStage,
                entry, reachability);
        result.stages.add(propagation);

        if (rawFlow.isYes()) {
            result.vulnerabilityConclusion = "flow_observed";
            result.summary = "A raw Tai-e flow matched the exact source/sink selector. "
                    + "The flow is endpoint evidence; it is not a proven hop-by-hop exploit path.";
        } else if (allRequiredYes(rule, sourceStage, entry, reachability, rawFlow)) {
            result.vulnerabilityConclusion = "not_observed_not_proven_absent";
            result.summary = "No matching flow was captured, but this is not proof that the "
                    + "vulnerability is absent.";
        } else {
            result.vulnerabilityConclusion = "unknown";
            result.summary = "Evidence stopped before a conclusive raw-flow result.";
        }
        result.limits.put("maxCallers", options.maxCallers());
        result.limits.put("maxTargetInvokes", options.maxTargetInvokes());
        if (workerResult.diagnostic != null && workerResult.diagnostic.limits != null) {
            result.limits.putAll(workerResult.diagnostic.limits);
        }
        addSuggestedChecks(result, sink, source);
        return writeAndReturn(result, workerDir, EXIT_OK);
    }

    protected RuleManager createRuleManager(Config config) {
        return new RuleManager(config);
    }

    private DiagnosisStage checkInvocation(TaiEMethodSignature sink, int maxCallers) {
        List<InvocationScanner.ArtifactPath> artifacts = new ArrayList<>();
        for (String path : context.targetAppJars()) {
            artifacts.add(new InvocationScanner.ArtifactPath(path, "TARGET_APP"));
        }
        for (String path : context.depAppJars()) {
            artifacts.add(new InvocationScanner.ArtifactPath(path, "DEP_APP"));
        }
        InvocationScanner.ScanResult scan;
        try {
            scan = InvocationScanner.scan(artifacts, sink, maxCallers);
        } catch (Exception e) {
            DiagnosisStage stage = DiagnosisStage.of("invocation", EvidenceState.UNKNOWN,
                    "Bytecode invocation scan failed: " + e.getMessage(),
                    DiagnosisStage.BYTECODE);
            stage.detail("error", e.toString());
            return stage;
        }
        DiagnosisStage stage;
        if (!scan.matches().isEmpty()) {
            stage = DiagnosisStage.of("invocation", EvidenceState.YES,
                    "Exact invoke found in " + scan.matches().size() + " caller site(s).",
                    DiagnosisStage.BYTECODE);
        } else if (!scan.errors().isEmpty()) {
            stage = DiagnosisStage.of("invocation", EvidenceState.UNKNOWN,
                    "No exact invoke was found, but one or more artifacts could not be read.",
                    DiagnosisStage.BYTECODE);
        } else {
            stage = DiagnosisStage.of("invocation", EvidenceState.NO,
                    "No exact invoke with matching owner, name, descriptor, and return type "
                            + "was found in target/dependency application bytecode.",
                    DiagnosisStage.BYTECODE);
        }
        stage.detail("targetInvokeKey", sink.invokeKey());
        stage.detail("artifactsScanned", scan.artifactsScanned());
        stage.detail("totalMatches", scan.totalMatches());
        stage.detail("truncated", scan.truncated());
        stage.detail("errors", scan.errors());
        int shown = 0;
        for (InvocationScanner.InvocationEvidence match : scan.matches()) {
            if (shown++ >= 25) {
                stage.detail("evidenceTruncatedAt", 25);
                break;
            }
            stage.reference(
                    "artifactPath", match.artifactPath(),
                    "artifactRole", match.artifactRole(),
                    "callerSignature", match.callerSignature(),
                    "lineNumber", match.lineNumber(),
                    "invokeKey", match.owner().replace('.', '/') + "."
                            + match.methodName() + match.descriptor());
        }
        return stage;
    }

    private DiagnosisStage checkRule(TaiEMethodSignature sink, String requestedIndex,
                                     SinkRule sinkRule,
                                     TaintConfigInspector.EmittedConfig emitted,
                                     String generationError, String taintConfigPath) {
        DiagnosisStage stage;
        if (sinkRule == null) {
            stage = DiagnosisStage.of("rule", EvidenceState.NO,
                    "The exact sink signature is not configured in rules.yaml.",
                    DiagnosisStage.CONFIG);
            stage.detail("configuredIndexes", List.of());
            return stage;
        }
        List<String> indexes = configuredSinkIndexes(sinkRule, sink);
        boolean indexConfigured = requestedIndex == null
                ? !indexes.isEmpty() : indexes.contains(requestedIndex);
        boolean emittedExact = generatedHasSink(emitted, sink, requestedIndex);
        boolean readErrors = emitted != null && !emitted.errors().isEmpty();
        EvidenceState ruleState;
        String ruleSummary;
        if (generationError != null) {
            ruleState = EvidenceState.UNKNOWN;
            ruleSummary = "Tai-e configuration generation failed: " + generationError;
        } else if (!indexConfigured) {
            ruleState = EvidenceState.NO;
            ruleSummary = "The requested sensitive index is not configured for this sink.";
        } else if (emittedExact) {
            ruleState = EvidenceState.YES;
            ruleSummary = "The exact sink and sensitive index were emitted into the Tai-e config.";
        } else if (readErrors) {
            ruleState = EvidenceState.UNKNOWN;
            ruleSummary = "The exact sink was not observed in readable config shards, but one "
                    + "or more shards could not be read; emitted evidence is partial.";
        } else {
            ruleState = EvidenceState.NO;
            ruleSummary = "The sink is configured but was not emitted; it may not be referenced "
                    + "in application bytecode or may be inactive.";
        }
        stage = DiagnosisStage.of("rule", ruleState, ruleSummary, DiagnosisStage.CONFIG);
        stage.detail("vulnType", sinkRule.getVulnType());
        stage.detail("category", sinkRule.getCategory());
        stage.detail("configuredIndexes", indexes);
        stage.detail("requestedIndex", requestedIndex);
        stage.detail("emittedIndexes", emitted == null ? List.of()
                : emitted.sinkIndexes(sink.canonical()));
        stage.detail("taintConfigPath", taintConfigPath);
        stage.detail("callSiteMode", emitted == null ? null : emitted.callSiteMode());
        if (emitted != null && !emitted.errors().isEmpty()) {
            stage.detail("configReadErrors", emitted.errors());
        }
        if (generationError != null) {
            stage.detail("generationError", generationError);
        }
        if (emittedExact) {
            stage.reference("ruleIdentity", sink.canonical(),
                    "index", requestedIndex == null ? "*" : requestedIndex,
                    "taintConfigPath", taintConfigPath);
        }
        return stage;
    }

    private DiagnosisStage checkSource(TaiEMethodSignature source, String requestedIndex,
                                       TaintConfigInspector.EmittedConfig emitted,
                                       String generationError, List<String> entrySignatures) {
        DiagnosisStage stage = DiagnosisStage.of("source", EvidenceState.UNKNOWN,
                "Source evidence unavailable.", DiagnosisStage.CONFIG);
        stage.detail("entrySignatureCount", entrySignatures.size());
        boolean readErrors = emitted != null && !emitted.errors().isEmpty();
        if (readErrors) {
            stage.detail("configReadErrors", emitted.errors());
        }
        if (generationError != null) {
            stage.state = EvidenceState.UNKNOWN;
            stage.summary = "Tai-e source configuration could not be verified: "
                    + generationError;
            return stage;
        }
        int emittedSourceCount = emitted == null ? 0 : emitted.sources().size();
        if (source == null) {
            if (emittedSourceCount > 0) {
                stage.state = EvidenceState.YES;
                stage.summary = "At least one configured source was emitted into the Tai-e config.";
                stage.detail("sourceCount", emittedSourceCount);
            } else if (readErrors) {
                stage.state = EvidenceState.UNKNOWN;
                stage.summary = "No sources were observed in readable config shards, but one or "
                        + "more shards could not be read.";
            } else {
                stage.state = EvidenceState.NO;
                stage.summary = "No sources were emitted into the Tai-e configuration.";
            }
            return stage;
        }
        List<TaintConfigInspector.EmittedSource> matches = emitted == null
                ? List.of() : emitted.sourcesFor(source.canonical());
        boolean emittedSource = generatedHasSource(emitted, source, requestedIndex);
        boolean entrySource = isEntrySignature(source, entrySignatures);
        boolean explicitRule = explicitRuleHasSource(source, requestedIndex);
        stage.detail("matchedSources", sourceRefs(matches));
        stage.detail("sourceIsEntry", entrySource);
        stage.detail("sourceIsExplicitRule", explicitRule);
        if (emittedSource) {
            stage.state = EvidenceState.YES;
            stage.summary = "The exact source signature and selected index were emitted.";
            stage.reference("sourceSignature", source.canonical(),
                    "index", requestedIndex == null ? "*" : requestedIndex);
        } else if (readErrors) {
            stage.state = EvidenceState.UNKNOWN;
            stage.summary = "The selected source was not observed in readable config shards, "
                    + "but one or more shards could not be read; emitted evidence is partial.";
        } else if (explicitRule) {
            stage.state = EvidenceState.NO;
            stage.summary = "The explicit source rule exists but was not emitted with the "
                    + "selected index.";
        } else {
            stage.state = EvidenceState.NO;
            stage.summary = "The exact source signature/index is not present in api.txt or "
                    + "explicit source rules.";
        }
        return stage;
    }

    private DiagnosisStage checkEntry(TaiEMethodSignature source, DiagnosisStage sourceStage,
                                      TaintConfigInspector.EmittedConfig emitted,
                                      TaieWorkerResult workerResult) {
        DiagnosisStage stage = DiagnosisStage.of("entry", EvidenceState.UNKNOWN,
                "Entry injection evidence unavailable.", DiagnosisStage.ENTRY);
        TargetDiagnosticEvidence diagnostic = workerResult.diagnostic;
        if (source != null) {
            List<TaintConfigInspector.EmittedSource> emittedSources =
                    emitted.sourcesFor(source.canonical());
            boolean callSource = emittedSources.stream()
                    .anyMatch(item -> "call".equals(item.kind()));
            if (callSource) {
                stage.state = EvidenceState.YES;
                stage.summary = "The selected source is an explicit call rule; entry injection "
                        + "is not required for it.";
                stage.detail("reason", "SOURCE_IS_CALL_RULE");
                return stage;
            }
            if (diagnostic == null || diagnostic.entryChecks == null
                    || diagnostic.entryChecks.isEmpty()) {
                stage.summary = "No worker entry check was recorded for the selected source.";
                return stage;
            }
            EntryCheckEvidence check = null;
            for (EntryCheckEvidence candidate : diagnostic.entryChecks) {
                if (source.canonical().equals(TaiEMethodSignature.canonicalize(
                        candidate.signature))) {
                    check = candidate;
                    break;
                }
            }
            if (check == null) {
                stage.summary = "The selected source was not present in the worker's entry "
                        + "injection list.";
                return stage;
            }
            stage.detail("entryStatus", check.status);
            stage.detail("inApplicationScope", check.inApplicationScope);
            stage.detail("declaringClassPhantom", check.declaringClassPhantom);
            if (check.detail != null) {
                stage.detail("entryDetail", check.detail);
            }
            if ("INJECTED".equals(check.status)) {
                stage.state = EvidenceState.YES;
                stage.summary = "The selected entry method resolved to a body and was injected.";
            } else if ("NOT_IN_ENTRY_LIST".equals(check.status)) {
                stage.state = sourceStage.isYes() ? EvidenceState.YES : EvidenceState.NO;
                stage.summary = sourceStage.isYes()
                        ? "Source is configured but is not an entry method; no entry is required."
                        : "Source is not an entry method and was not otherwise configured.";
                stage.detail("reason", "SOURCE_NOT_ENTRY");
            } else {
                stage.state = EvidenceState.NO;
                stage.summary = "Entry injection failed: " + check.status;
            }
            return stage;
        }

        Map<String, Object> inject = workerResult.expansionInject != null
                ? workerResult.expansionInject : Map.of();
        int candidates = intValue(inject.get("entryCandidates"), -1);
        int injected = intValue(inject.get("entryInjected"), -1);
        int unresolved = intValue(inject.get("entryUnresolved"), 0);
        int noBody = intValue(inject.get("entryNoBodySkipped"), 0);
        int duplicates = intValue(inject.get("entryMethodIdentityDupSkipped"), 0);
        stage.detail("entryCandidates", candidates);
        stage.detail("entryInjected", injected);
        stage.detail("entryUnresolved", unresolved);
        stage.detail("entryNoBodySkipped", noBody);
        stage.detail("entryMethodIdentityDupSkipped", duplicates);
        if (candidates < 0 || injected < 0) {
            stage.summary = "Worker did not report entry injection counts.";
            return stage;
        }
        if (candidates == 0) {
            stage.state = EvidenceState.NO;
            stage.summary = "No entry methods were candidates for injection.";
        } else if (injected > 0) {
            stage.state = EvidenceState.YES;
            stage.summary = "At least one entry method was injected.";
        } else {
            stage.state = EvidenceState.NO;
            stage.summary = "Entry methods were candidates but none were injected.";
        }
        return stage;
    }

    private DiagnosisStage checkReachability(DiagnosisStage invocation,
                                             TaieWorkerResult workerResult) {
        DiagnosisStage stage = DiagnosisStage.of("reachability", EvidenceState.UNKNOWN,
                "Worker reachability evidence unavailable.", DiagnosisStage.REACHABILITY);
        TargetDiagnosticEvidence diagnostic = workerResult.diagnostic;
        if (diagnostic == null) {
            return stage;
        }
        stage.detail("callGraphAvailable", diagnostic.callGraphAvailable);
        stage.detail("reachableMethodCount", diagnostic.reachableMethodCount);
        stage.detail("reachableScanTruncated", diagnostic.reachableScanTruncated);
        stage.detail("applicationMethodsScanned", diagnostic.applicationMethodsScanned);
        stage.detail("irScanTruncated", diagnostic.irScanTruncated);
        if (diagnostic.notes != null && !diagnostic.notes.isEmpty()) {
            stage.detail("workerNotes", diagnostic.notes);
        }
        if (diagnostic.limits != null) {
            stage.detail("workerLimits", diagnostic.limits);
        }
        List<TargetInvokeEvidence> invokes = diagnostic.targetInvokes == null
                ? List.of() : diagnostic.targetInvokes;
        stage.detail("targetInvokeCount", invokes.size());
        int shown = 0;
        for (TargetInvokeEvidence invoke : invokes) {
            if (shown++ >= 25) {
                stage.detail("evidenceTruncatedAt", 25);
                break;
            }
            stage.reference(
                    "containerSignature", invoke.containerSignature,
                    "stmtIndex", invoke.stmtIndex,
                    "lineNumber", invoke.lineNumber,
                    "callerReachable", invoke.callerReachable,
                    "callEdgeObserved", invoke.callEdgeObserved,
                    "calleeReachable", invoke.calleeReachable,
                    "resolvedSignature", invoke.resolvedSignature,
                    "resolvedCallees", invoke.resolvedCallees);
        }
        if (invokes.isEmpty()) {
            if (diagnostic.irScanTruncated) {
                stage.summary = "Application IR scan was truncated before target invokes "
                        + "could be conclusively located.";
                return stage;
            }
            if (invocation != null && invocation.isYes()) {
                stage.summary = "The bytecode invoke exists outside the Tai-e application IR "
                        + "scope, so reachability cannot be decided from this worker.";
            } else {
                stage.state = EvidenceState.NO;
                stage.summary = "No target invoke exists in the application, so it cannot be "
                        + "reachable.";
            }
            return stage;
        }
        boolean anyReachable = invokes.stream().anyMatch(item -> item.callerReachable);
        boolean anyEdge = invokes.stream().anyMatch(item -> item.callEdgeObserved);
        if (anyReachable) {
            stage.state = EvidenceState.YES;
            stage.summary = anyEdge
                    ? "A target invoke is inside a PTA-reachable caller; call-edge evidence "
                    + "was also observed."
                    : "A target invoke is inside a PTA-reachable caller. No concrete callee "
                    + "edge was observed (common for only-application library sinks).";
        } else if (diagnostic.reachableScanTruncated) {
            stage.state = EvidenceState.UNKNOWN;
            stage.summary = "Reachability scan was truncated before a conclusion.";
        } else {
            stage.state = EvidenceState.NO;
            stage.summary = "Target invokes were found, but their caller methods were not "
                    + "reachable in the PTA call graph.";
        }
        return stage;
    }

    private DiagnosisStage checkRawFlow(List<CapturedTaintFlow> matched,
                                        TaieWorkerResult workerResult,
                                        DiagnosisStage rule, DiagnosisStage source,
                                        DiagnosisStage entry, DiagnosisStage reachability) {
        DiagnosisStage stage = DiagnosisStage.of("raw_flow", EvidenceState.UNKNOWN,
                "Raw flow evidence unavailable.", DiagnosisStage.TAINT);
        stage.detail("rawFlowCount", workerResult.taintFlows == null
                ? 0 : workerResult.taintFlows.size());
        stage.detail("matchedFlowCount", matched.size());
        int shown = 0;
        for (CapturedTaintFlow flow : matched) {
            if (shown++ >= 25) {
                stage.detail("evidenceTruncatedAt", 25);
                break;
            }
            stage.reference(
                    "sourceContainerSignature", flow.sourceContainerSignature,
                    "sourceRuleSignature", flow.sourceRuleSignature,
                    "sourceIndex", flow.sourceIndex,
                    "sinkRuleSignature", flow.sinkRuleSignature,
                    "sinkIndex", flow.sinkIndex,
                    "sinkContainerSignature", flow.sinkContainerSignature,
                    "sinkStmtIndex", flow.sinkStmtIndex,
                    "sinkLineNumber", flow.sinkLineNumber);
        }
        if (!matched.isEmpty()) {
            stage.state = EvidenceState.YES;
            stage.summary = "A raw Tai-e flow matched the exact source/sink selector. "
                    + "This is endpoint evidence, not a hop-by-hop path.";
            return stage;
        }
        List<String> incomplete = new ArrayList<>();
        if (!rule.isYes()) {
            incomplete.add("rule");
        }
        if (!source.isYes()) {
            incomplete.add("source");
        }
        if (!entry.isYes()) {
            incomplete.add("entry");
        }
        if (!reachability.isYes()) {
            incomplete.add("reachability");
        }
        stage.detail("incompletePrerequisites", incomplete);
        if (incomplete.isEmpty()) {
            stage.state = EvidenceState.NO;
            stage.summary = "Tai-e completed with the exact sink/source configured but captured "
                    + "no matching flow. This does not prove the flow is impossible.";
        } else {
            stage.summary = "No matching flow was captured, but prerequisite evidence is "
                    + "incomplete: " + String.join(", ", incomplete);
        }
        return stage;
    }

    private DiagnosisStage checkDisposition(List<CapturedTaintFlow> matched,
                                            TaieWorkerResult workerResult,
                                            RuleManager ruleManager,
                                            TaiEMethodSignature sink,
                                            String requestedIndex,
                                            DiagnosisResult result) {
        DiagnosisStage stage = DiagnosisStage.of("finding_disposition", EvidenceState.UNKNOWN,
                "No matching raw flow to place.", DiagnosisStage.FINDING_DISPOSITION);
        if (matched.isEmpty()) {
            stage.detail("reason", "NO_RAW_FLOW");
            return stage;
        }
        try {
            ScanConfig scanConfig = context.configManager() != null
                    && context.configManager().getConfig() != null
                    ? context.configManager().getConfig().getScanConfig() : null;
            FindingPipeline pipeline = new FindingPipeline(ruleManager, scanConfig,
                    context.routes());
            List<CapturedTaintFlow> allFlows = workerResult.taintFlows == null
                    ? List.of() : workerResult.taintFlows;
            PipelineResult pipelineResult = pipeline.process(allFlows);
            List<FindingDispositionEvidence> placements = new ArrayList<>();
            collectDispositions(placements, pipelineResult.mainFindings, "main", sink,
                    requestedIndex, matched);
            collectDispositions(placements, pipelineResult.lowConfidenceFindings,
                    "low_confidence", sink, requestedIndex, matched);
            collectDispositions(placements, pipelineResult.suppressedFindings,
                    "suppressed", sink, requestedIndex, matched);
            stage.detail("mainCount", pipelineResult.mainFindings.size());
            stage.detail("lowConfidenceCount", pipelineResult.lowConfidenceFindings.size());
            stage.detail("suppressedCount", pipelineResult.suppressedFindings.size());
            if (placements.isEmpty()) {
                stage.state = EvidenceState.NO;
                stage.summary = "The raw flow matched, but the finding pipeline produced no "
                        + "target finding.";
            } else {
                stage.state = EvidenceState.YES;
                stage.summary = "The matched flow was placed by the finding pipeline.";
                for (FindingDispositionEvidence placement : placements) {
                    stage.reference(
                            "findingId", placement.findingId,
                            "disposition", placement.disposition,
                            "reasonCodes", placement.reasonCodes);
                }
            }
            result.findingDispositions.addAll(placements);
            return stage;
        } catch (Throwable t) {
            stage.summary = "Finding pipeline evaluation failed: " + t;
            stage.detail("error", t.toString());
            return stage;
        }
    }

    private void collectDispositions(List<FindingDispositionEvidence> out,
                                     List<CanonicalFinding> findings, String disposition,
                                     TaiEMethodSignature sink, String requestedIndex,
                                     List<CapturedTaintFlow> matched) {
        for (CanonicalFinding finding : findings) {
            if (!signatureMatches(finding.sinkRuleSignature, sink)) {
                continue;
            }
            if (requestedIndex != null
                    && !requestedIndex.equals(TaiEMethodSignature.normalizeIndex(
                    finding.sinkIndex))) {
                continue;
            }
            List<FindingInstance> matchingInstances = new ArrayList<>();
            for (FindingInstance instance : finding.instances == null
                    ? List.<FindingInstance>of() : finding.instances) {
                if (matchesAnyFlow(instance, finding, matched)) {
                    matchingInstances.add(instance);
                }
            }
            if (matchingInstances.isEmpty()) {
                continue;
            }
            FindingDispositionEvidence item = new FindingDispositionEvidence();
            item.findingId = finding.ruleId + "|" + finding.sinkRuleSignature + "|"
                    + finding.sinkIndex + "|" + finding.sinkContainerSignature + "|"
                    + finding.sinkStmtIndex;
            item.disposition = disposition;
            item.ruleId = finding.ruleId;
            item.sinkRuleSignature = finding.sinkRuleSignature;
            item.sinkIndex = finding.sinkIndex;
            item.sinkContainerSignature = finding.sinkContainerSignature;
            item.sinkStmtIndex = finding.sinkStmtIndex;
            item.sourceCount = finding.sourceCount;
            item.reasonCodes = finding.reasonCodes == null
                    ? new ArrayList<>() : new ArrayList<>(finding.reasonCodes);
            item.sourceSignatures = new ArrayList<>();
            for (FindingInstance instance : matchingInstances) {
                if (instance.sourceContainerSignature != null
                        && !item.sourceSignatures.contains(instance.sourceContainerSignature)) {
                    item.sourceSignatures.add(instance.sourceContainerSignature);
                }
            }
            out.add(item);
        }
    }

    private boolean matchesAnyFlow(FindingInstance instance, CanonicalFinding finding,
                                   List<CapturedTaintFlow> matched) {
        for (CapturedTaintFlow flow : matched) {
            if (!sameSignature(instance.sourceRuleSignature, flow.sourceRuleSignature)) {
                continue;
            }
            if (!sameSignature(instance.sourceContainerSignature,
                    flow.sourceContainerSignature)) {
                continue;
            }
            if (!sameIndex(instance.sourceIndex, flow.sourceIndex)) {
                continue;
            }
            if (!sameSignature(finding.sinkRuleSignature, flow.sinkRuleSignature)) {
                continue;
            }
            if (!sameIndex(finding.sinkIndex, flow.sinkIndex)) {
                continue;
            }
            if (!sameSignature(finding.sinkContainerSignature,
                    flow.sinkContainerSignature)) {
                continue;
            }
            if (finding.sinkStmtIndex != flow.sinkStmtIndex) {
                continue;
            }
            return true;
        }
        return false;
    }

    private boolean sameSignature(String left, String right) {
        if (left == null || right == null) {
            return left == null && right == null;
        }
        String leftCanonical = TaiEMethodSignature.canonicalize(left);
        String rightCanonical = TaiEMethodSignature.canonicalize(right);
        return leftCanonical != null && leftCanonical.equals(rightCanonical);
    }

    private boolean sameIndex(String left, String right) {
        return java.util.Objects.equals(TaiEMethodSignature.normalizeIndex(left),
                TaiEMethodSignature.normalizeIndex(right));
    }

    private DiagnosisStage checkPropagation(DiagnosisStage rawFlow,
                                            TaieWorkerResult workerResult,
                                            DiagnosisStage rule, DiagnosisStage source,
                                            DiagnosisStage entry, DiagnosisStage reachability) {
        DiagnosisStage stage = DiagnosisStage.of("propagation_frontier", EvidenceState.UNKNOWN,
                "Propagation frontier is not exposed by Tai-e 0.5.4.", DiagnosisStage.INFERENCE);
        stage.detail("lastProvenTaintLocation", null);
        stage.detail("candidateUnmodeledTransfer", null);
        stage.detail("apiLimitation",
                "Tai-e exposes completed endpoint taint flows, not intermediate taint facts "
                        + "inside a method. JByteScanner will not fabricate a frontier.");
        if (rawFlow.isYes()) {
            stage.detail("notEvaluated", true);
            stage.detail("reason", "RAW_FLOW_CAPTURED");
            stage.summary = "Not evaluated because a matching raw flow was captured.";
            return stage;
        }
        boolean prerequisites = rule.isYes() && source.isYes() && entry.isYes()
                && reachability.isYes();
        if (!prerequisites) {
            stage.detail("reason", "PREREQUISITE_EVIDENCE_INCOMPLETE");
            stage.summary = "Bounded propagation facts were not requested because prerequisite "
                    + "evidence is incomplete.";
            return stage;
        }
        TargetDiagnosticEvidence diagnostic = workerResult.diagnostic;
        if (diagnostic == null) {
            stage.detail("reason", "WORKER_DIAGNOSTIC_MISSING");
            return stage;
        }
        List<Map<String, Object>> localFacts = new ArrayList<>();
        int shown = 0;
        for (TargetInvokeEvidence invoke : diagnostic.targetInvokes == null
                ? List.<TargetInvokeEvidence>of() : diagnostic.targetInvokes) {
            if (shown++ >= 10) {
                stage.detail("localFactsTruncated", true);
                break;
            }
            Map<String, Object> fact = new LinkedHashMap<>();
            fact.put("containerSignature", invoke.containerSignature);
            fact.put("stmtIndex", invoke.stmtIndex);
            fact.put("lineNumber", invoke.lineNumber);
            fact.put("callerReachable", invoke.callerReachable);
            fact.put("callEdgeObserved", invoke.callEdgeObserved);
            fact.put("resolvedCallees", invoke.resolvedCallees);
            localFacts.add(fact);
        }
        stage.detail("localFacts", localFacts);
        stage.detail("reason", "TAINT_FRONTIER_NOT_EXPOSED");
        stage.summary = "Prerequisites passed, but Tai-e does not expose the intermediate "
                + "propagation frontier. Only bounded invoke/call-edge facts are available; "
                + "no last-taint location or unmodeled transfer is claimed.";
        return stage;
    }

    private void addNotRunStages(DiagnosisResult result, boolean ruleOk, boolean sourceOk,
                                 boolean workerRequested, String generationError,
                                 DiagnosisStage invocation) {
        result.stages.add(DiagnosisStage.of("entry", EvidenceState.UNKNOWN,
                workerRequested
                        ? "Entry injection was not evaluated because rule/source prerequisites failed."
                        : "Targeted worker was not requested.",
                DiagnosisStage.ENTRY));
        result.stages.add(DiagnosisStage.of("reachability", EvidenceState.UNKNOWN,
                "Reachability was not evaluated because targeted analysis did not run.",
                DiagnosisStage.REACHABILITY));
        result.stages.add(DiagnosisStage.of("raw_flow", EvidenceState.UNKNOWN,
                "Raw flow was not evaluated because targeted analysis did not run.",
                DiagnosisStage.TAINT));
        result.stages.add(DiagnosisStage.of("finding_disposition", EvidenceState.UNKNOWN,
                "Finding disposition is unknown without a raw flow.",
                DiagnosisStage.FINDING_DISPOSITION));
        result.stages.add(DiagnosisStage.of("propagation_frontier", EvidenceState.UNKNOWN,
                "Propagation frontier is unknown without a completed targeted analysis.",
                DiagnosisStage.INFERENCE));
        result.limits.put("ruleOk", ruleOk);
        result.limits.put("sourceOk", sourceOk);
        result.limits.put("generationError", generationError);
        if (invocation != null && invocation.isYes()) {
            result.limits.put("note",
                    "Exact invoke exists, but rule/source prerequisites prevent targeted analysis.");
        }
    }

    private void addWorkerFailureStages(DiagnosisResult result, TaieWorkerResult workerResult) {
        String detail = workerResult == null ? "worker returned null"
                : workerResult.status + ": " + workerResult.errorClass + " "
                + workerResult.errorMessage;
        result.stages.add(DiagnosisStage.of("entry", EvidenceState.UNKNOWN,
                "Entry evidence is unknown because the worker did not complete: " + detail,
                DiagnosisStage.ENTRY));
        result.stages.add(DiagnosisStage.of("reachability", EvidenceState.UNKNOWN,
                "Reachability is unknown because the worker did not complete.",
                DiagnosisStage.REACHABILITY));
        result.stages.add(DiagnosisStage.of("raw_flow", EvidenceState.UNKNOWN,
                "Raw flow is unknown because the worker did not complete.",
                DiagnosisStage.TAINT));
        result.stages.add(DiagnosisStage.of("finding_disposition", EvidenceState.UNKNOWN,
                "Finding disposition is unknown because the worker did not complete.",
                DiagnosisStage.FINDING_DISPOSITION));
        result.stages.add(DiagnosisStage.of("propagation_frontier", EvidenceState.UNKNOWN,
                "Propagation frontier is unknown because the worker did not complete.",
                DiagnosisStage.INFERENCE));
    }

    private TaieWorkerRequest buildWorkerRequest(TaiEMethodSignature sink,
                                                 TaiEMethodSignature source,
                                                 String sinkIndex, String sourceIndex,
                                                 List<String> entrySignatures,
                                                 String taintConfigPath,
                                                 int maxTargetInvokes, Path workerDir) {
        TaieWorkerRequest request = new TaieWorkerRequest();
        request.workspaceDir = context.workspace().toString();
        request.outputDir = workerDir.toString();
        request.targetAppJars.addAll(context.targetAppJars());
        List<String> classPath = new ArrayList<>();
        classPath.addAll(context.libJars());
        classPath.addAll(context.depAppJars());
        request.classPathJars.addAll(classPath);
        request.entrySignatures.addAll(entrySignatures);
        if (JBSScanEntryPointPlugin.supplementalEntrySignatures != null) {
            request.supplementalEntrySignatures.addAll(
                    JBSScanEntryPointPlugin.supplementalEntrySignatures);
        }
        request.taintConfigPath = taintConfigPath;
        ScanConfig scanConfig = context.configManager() != null
                && context.configManager().getConfig() != null
                ? context.configManager().getConfig().getScanConfig() : null;
        request.springAnalysis = scanConfig == null || scanConfig.isSpringAnalysis();
        request.springServiceEntryFallback =
                scanConfig == null || scanConfig.isSpringServiceEntryFallback();
        request.taintCallSiteMode = scanConfig == null || scanConfig.isTaintCallSiteMode();
        request.batchId = workerDir.getFileName().toString();
        ResourceBudget budget = context.budget();
        request.executionMode = budget != null && budget.getExecutionMode() != null
                ? budget.getExecutionMode() : "single";

        TargetDiagnosticRequest diagnostic = new TargetDiagnosticRequest();
        diagnostic.sinkSignature = sink.canonical();
        diagnostic.sinkIndex = sinkIndex;
        diagnostic.sourceSignature = source == null ? null : source.canonical();
        diagnostic.sourceIndex = sourceIndex;
        diagnostic.maxTargetInvokes = maxTargetInvokes;
        if (source != null && entrySignatures.contains(source.canonical())) {
            diagnostic.entrySignaturesToCheck.add(source.canonical());
        }
        request.diagnosticTarget = diagnostic;
        return request;
    }

    private void fillWorkerSummary(DiagnosisWorkerSummary summary,
                                   TaieWorkerResult workerResult) {
        if (workerResult == null) {
            summary.status = TaieWorkerResult.STATUS_FAILED;
            summary.exitCode = 1;
            summary.errorMessage = "worker returned null";
            summary.diagnosticAvailable = false;
            return;
        }
        summary.status = workerResult.status;
        summary.exitCode = workerResult.exitCode;
        summary.worldCompleted = workerResult.worldCompleted;
        summary.analysisCompleted = workerResult.analysisCompleted;
        summary.totalMs = workerResult.totalMs;
        summary.worldMs = workerResult.worldMs;
        summary.ptaMs = workerResult.ptaMs;
        summary.errorClass = workerResult.errorClass;
        summary.errorMessage = workerResult.errorMessage;
        summary.diagnosticAvailable = workerResult.diagnostic != null;
    }

    private List<CapturedTaintFlow> matchedFlows(TaieWorkerResult workerResult,
                                                 TaiEMethodSignature sink,
                                                 TaiEMethodSignature source,
                                                 String sinkIndex, String sourceIndex) {
        List<CapturedTaintFlow> matched = new ArrayList<>();
        if (workerResult == null || workerResult.taintFlows == null) {
            return matched;
        }
        for (CapturedTaintFlow flow : workerResult.taintFlows) {
            if (flow == null || !signatureMatches(flow.sinkRuleSignature, sink)) {
                continue;
            }
            if (sinkIndex != null && !sinkIndex.equals(
                    TaiEMethodSignature.normalizeIndex(flow.sinkIndex))) {
                continue;
            }
            if (source != null && !flowSourceMatches(flow, source, sourceIndex)) {
                continue;
            }
            matched.add(flow);
        }
        return matched;
    }

    private boolean flowSourceMatches(CapturedTaintFlow flow, TaiEMethodSignature source,
                                      String sourceIndex) {
        if (!signatureMatches(flow.sourceRuleSignature, source)) {
            return false;
        }
        return sourceIndex == null || sourceIndex.equals(
                TaiEMethodSignature.normalizeIndex(flow.sourceIndex));
    }

    private boolean signatureMatches(String raw, TaiEMethodSignature expected) {
        if (raw == null || expected == null) {
            return false;
        }
        TaiEMethodSignature parsed = TaiEMethodSignature.parseNullable(raw);
        return parsed != null && parsed.sameMethod(expected);
    }

    private boolean generatedHasSink(TaintConfigInspector.EmittedConfig emitted,
                                     TaiEMethodSignature sink, String index) {
        return emitted != null && emitted.hasSink(sink.canonical(), index);
    }

    private boolean generatedHasSource(TaintConfigInspector.EmittedConfig emitted,
                                       TaiEMethodSignature source, String index) {
        return emitted != null && emitted.hasSource(source.canonical(), index);
    }

    private boolean explicitRuleHasSource(TaiEMethodSignature source, String index) {
        Config config = context.configManager() != null
                ? context.configManager().getConfig() : null;
        if (config == null || config.getSources() == null) {
            return false;
        }
        String wantedIndex = index == null ? "result" : index;
        return config.getSources().stream().anyMatch(rule -> {
            if (rule.getSignature() == null) {
                return false;
            }
            TaiEMethodSignature parsed = TaiEMethodSignature.parseNullable(rule.getSignature());
            if (parsed == null || !parsed.sameMethod(source)) {
                return false;
            }
            String ruleIndex = rule.getIndex() == null
                    ? "result" : TaiEMethodSignature.normalizeIndex(rule.getIndex());
            return index == null || wantedIndex.equals(ruleIndex);
        });
    }

    private boolean isEntrySignature(TaiEMethodSignature source, List<String> entrySignatures) {
        for (String entry : entrySignatures) {
            TaiEMethodSignature parsed = TaiEMethodSignature.parseNullable(entry);
            if (parsed != null && parsed.sameMethod(source)) {
                return true;
            }
        }
        return false;
    }

    private SinkRule findSinkRule(Config config, TaiEMethodSignature sink) {
        if (config == null || config.getSinks() == null) {
            return null;
        }
        for (SinkRule rule : config.getSinks()) {
            if (rule.getSignature() == null) {
                continue;
            }
            TaiEMethodSignature parsed = TaiEMethodSignature.parseNullable(rule.getSignature());
            if (parsed != null && parsed.sameMethod(sink)) {
                return rule;
            }
        }
        return null;
    }

    private List<String> configuredSinkIndexes(SinkRule rule, TaiEMethodSignature sink) {
        List<String> indexes = new ArrayList<>();
        if (rule.getIndex() != null) {
            indexes.add(TaiEMethodSignature.normalizeIndex(rule.getIndex()));
            return indexes;
        }
        for (int i = 0; i < sink.parameterCount(); i++) {
            indexes.add(String.valueOf(i));
        }
        return indexes;
    }

    private List<String> entrySignatures(List<ApiRoute> routes) {
        List<String> raw = new ArrayList<>();
        for (ApiRoute route : routes) {
            if (route.getClassName() == null || route.getMethodSig() == null) {
                continue;
            }
            String signature = "<" + route.getClassName() + ": " + route.getMethodSig() + ">";
            TaiEMethodSignature parsed = TaiEMethodSignature.parseNullable(signature);
            raw.add(parsed != null ? parsed.canonical() : signature);
        }
        CanonicalIdentity.DedupResult dedup = CanonicalIdentity.dedupeOrdered(raw);
        return new ArrayList<>(dedup.uniqueItems());
    }

    private List<Map<String, Object>> sourceRefs(
            List<TaintConfigInspector.EmittedSource> sources) {
        List<Map<String, Object>> refs = new ArrayList<>();
        int shown = 0;
        for (TaintConfigInspector.EmittedSource source : sources) {
            if (shown++ >= 20) {
                break;
            }
            Map<String, Object> ref = new LinkedHashMap<>();
            ref.put("kind", source.kind());
            ref.put("method", source.method());
            ref.put("index", source.index());
            ref.put("type", source.type());
            refs.add(ref);
        }
        return refs;
    }

    private boolean allRequiredYes(DiagnosisStage rule, DiagnosisStage source,
                                   DiagnosisStage entry, DiagnosisStage reachability,
                                   DiagnosisStage rawFlow) {
        return rule.isYes() && source.isYes() && entry.isYes() && reachability.isYes()
                && rawFlow.state == EvidenceState.NO;
    }

    private String batchId(TaiEMethodSignature sink, TaiEMethodSignature source,
                           String sinkIndex, String sourceIndex) {
        String material = sink.canonical() + "|" + sinkIndex + "|"
                + (source == null ? "" : source.canonical()) + "|" + sourceIndex;
        return "diagnose-" + shortHash(material);
    }

    private static String shortHash(String material) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(material.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest, 0, 8);
        } catch (Exception e) {
            return Integer.toHexString(material.hashCode());
        }
    }

    private void addSuggestedChecks(DiagnosisResult result, TaiEMethodSignature sink,
                                    TaiEMethodSignature source) {
        Set<String> checks = new LinkedHashSet<>();
        DiagnosisStage invocation = result.stage("invocation");
        DiagnosisStage rule = result.stage("rule");
        DiagnosisStage sourceStage = result.stage("source");
        DiagnosisStage entry = result.stage("entry");
        DiagnosisStage reachability = result.stage("reachability");
        DiagnosisStage rawFlow = result.stage("raw_flow");
        DiagnosisStage disposition = result.stage("finding_disposition");
        if (invocation != null && invocation.state == EvidenceState.NO) {
            checks.add("Verify the exact sink owner, return type, method name, and parameter "
                    + "types: " + sink.canonical());
            checks.add("Confirm the caller artifact is in the application/dependency classpath "
                    + "used for this deployment.");
        }
        if (invocation != null && invocation.state == EvidenceState.UNKNOWN) {
            checks.add("Re-run invocation scan; some classpath artifacts could not be read.");
        }
        if (rule != null && rule.state == EvidenceState.NO) {
            checks.add("Add or fix the exact sink signature/index in rules.yaml, then retry.");
            checks.add("If the sink is not referenced in app bytecode, confirm the invocation "
                    + "artifact is loaded as target/dependency application code.");
        }
        if (sourceStage != null && sourceStage.state == EvidenceState.NO) {
            checks.add("Add the exact source signature/index to api.txt or rules.yaml sources.");
            checks.add("Run '-m api' to regenerate api.txt if the route list is incomplete.");
        }
        if (sourceStage != null && sourceStage.state == EvidenceState.UNKNOWN) {
            checks.add("Regenerate api.txt with '-m api' or verify the current source whitelist "
                    + "and Tai-e config shards.");
        }
        if (entry != null && entry.state == EvidenceState.NO) {
            checks.add("Inspect entry status (unresolved/phantom/abstract/native/no-body) in "
                    + "the worker tai-e.log, then fix the entry signature.");
        }
        if (reachability != null && !reachability.isYes()) {
            checks.add("Inspect the PTA call graph and entry injection counts; an invoke in "
                    + "bytecode does not prove reachability.");
        }
        if (rawFlow != null && rawFlow.state == EvidenceState.NO) {
            checks.add("No flow was captured. Review source/sink indexes and transfer summaries; "
                    + "zero findings do not prove the vulnerability is absent.");
        }
        if (disposition != null && disposition.isYes()) {
            checks.add("Review finding reasonCodes and noise_filter settings if the flow was "
                    + "suppressed or demoted.");
        }
        if (result.worker != null && result.worker.status != null
                && !TaieWorkerResult.STATUS_SUCCESS.equals(result.worker.status)
                && !"NOT_RUN".equals(result.worker.status)) {
            checks.add("Inspect worker-result.json and tai-e.log; increase heap/timeout if the "
                    + "worker failed or timed out.");
        }
        checks.add("A missing SARIF finding is not proof that no exploitable flow exists.");
        result.suggestedNextChecks.addAll(checks);
    }

    private int intValue(Object value, int fallback) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value != null) {
            try {
                return Integer.parseInt(value.toString());
            } catch (NumberFormatException ignored) {
                return fallback;
            }
        }
        return fallback;
    }

    private DiagnosisOutcome writeAndReturn(DiagnosisResult result, Path workerDir, int exitCode) {
        Path recordDir = workerDir != null
                ? workerDir
                : context.workspace().resolve("diagnosis").resolve("not-run-"
                + shortHash(result.target.sinkSignature + "|"
                + result.target.sourceSignature + "|" + result.target.sinkIndex + "|"
                + result.target.sourceIndex));
        try {
            Files.createDirectories(recordDir);
            Path record = recordDir.resolve("diagnosis.json");
            result.diagnosisRecordPath = record.toString();
            MAPPER.writeValue(record.toFile(), result);
            Path latest = context.workspace().resolve("diagnosis").resolve("latest.json");
            Files.createDirectories(latest.getParent());
            MAPPER.writeValue(latest.toFile(), result);
        } catch (Exception e) {
            result.error = "failed to write diagnosis record: " + e;
        }
        return new DiagnosisOutcome(result, exitCode);
    }
}
