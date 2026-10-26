package com.jbytescanner.diagnose;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.jbytescanner.finding.CanonicalFinding;
import com.jbytescanner.finding.FindingInstance;
import com.jbytescanner.worker.TaieWorkerRequest;
import com.jbytescanner.worker.TaieWorkerResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Offline query over existing scan artifacts. This class never launches Tai-e
 * and never turns an absent finding into a claim that the vulnerability is
 * absent.
 */
public class QueryService {

    public static final int EXIT_OK = 0;
    public static final int EXIT_WORKER_FAILED = 4;
    public static final int EXIT_UNAVAILABLE = 6;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final ObjectMapper OUTPUT = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL);

    private final Path requestedWorkspace;

    public QueryService(Path workspace) {
        this.requestedWorkspace = workspace;
    }

    public static Path resolveWorkspace(Path input) {
        if (input == null) {
            return null;
        }
        Path candidate = input.toAbsolutePath().normalize();
        Path nested = candidate.resolve(".jbytescanner");
        if (Files.isDirectory(nested)) {
            return nested;
        }
        return candidate;
    }

    public QueryOutcome query(QueryOptions options) {
        Path workspace = resolveWorkspace(requestedWorkspace);
        String what = options.what() == null ? "findings" : options.what().trim().toLowerCase();
        if ("findings".equals(what) || "finding".equals(what)) {
            return queryFindings(workspace, options, "finding".equals(what));
        }
        if ("scan-status".equals(what) || "status".equals(what)) {
            return scanStatus(workspace);
        }
        throw new IllegalArgumentException("Unknown query kind: " + options.what()
                + " (expected findings, finding, or scan-status)");
    }

    private QueryOutcome queryFindings(Path workspace, QueryOptions options, boolean single) {
        QueryResult result = baseResult(workspace, single ? "finding" : "findings");
        if (single && (options.sinkSignature() == null || options.sinkSignature().isBlank())) {
            throw new IllegalArgumentException("query finding requires --sink");
        }
        TaiEMethodSignature sink = options.sinkSignature() == null
                ? null : TaiEMethodSignature.parse(options.sinkSignature());
        TaiEMethodSignature source = options.sourceSignature() == null
                ? null : TaiEMethodSignature.parse(options.sourceSignature());
        String sinkIndex = TaiEMethodSignature.normalizeIndex(options.sinkIndex());
        String sourceIndex = TaiEMethodSignature.normalizeIndex(options.sourceIndex());

        List<Path> sidecars = sidecarFiles(workspace);
        boolean anyExists = false;
        boolean parseError = false;
        List<CanonicalFinding> all = new ArrayList<>();
        for (Path sidecar : sidecars) {
            addArtifact(result, workspace, sidecar);
            if (!Files.isRegularFile(sidecar)) {
                continue;
            }
            anyExists = true;
            try {
                for (String line : Files.readAllLines(sidecar, StandardCharsets.UTF_8)) {
                    if (line.isBlank()) {
                        continue;
                    }
                    all.add(MAPPER.readValue(line, CanonicalFinding.class));
                }
            } catch (Exception e) {
                parseError = true;
                result.notes.add("failed to parse " + sidecar.getFileName() + ": " + e);
            }
        }
        if (!anyExists) {
            result.evidenceState = EvidenceState.UNKNOWN;
            result.requiresTargetedDiagnosis = true;
            result.vulnerabilityConclusion = "unknown";
            result.notes.add("No findings-main.jsonl, low-confidence.jsonl, or "
                    + "results-suppressed.jsonl exists. Run a scan or targeted diagnose.");
            result.counts.put("totalRecords", 0);
            return new QueryOutcome(result, EXIT_UNAVAILABLE);
        }

        addArtifact(result, workspace, workspace.resolve("worker/single/worker-result.json"));
        addArtifact(result, workspace, workspace.resolve("worker/single/worker-request.json"));
        addArtifact(result, workspace, workspace.resolve("benchmark.json"));
        addWorkerSummary(result, workspace);

        List<CanonicalFinding> matched = new ArrayList<>();
        for (CanonicalFinding finding : all) {
            if (sink != null && !signatureMatches(finding.sinkRuleSignature, sink)) {
                continue;
            }
            if (sinkIndex != null && !sinkIndex.equals(
                    TaiEMethodSignature.normalizeIndex(finding.sinkIndex))) {
                continue;
            }
            if (source != null && !findingSourceMatches(finding, source, sourceIndex)) {
                continue;
            }
            matched.add(finding);
        }
        matched.sort(Comparator
                .comparing((CanonicalFinding f) -> String.valueOf(f.sinkRuleSignature))
                .thenComparingInt(f -> f.sinkStmtIndex));
        int limit = options.limit();
        if (matched.size() > limit) {
            result.notes.add("result list truncated at " + limit + " finding(s)");
            result.counts.put("truncated", true);
            matched = new ArrayList<>(matched.subList(0, limit));
        }
        result.findings = matched;
        result.counts.put("totalRecords", all.size());
        result.counts.put("matchedRecords", matched.size());
        result.counts.put("mainRecords", all.stream()
                .filter(f -> f.disposition != null
                        && "MAIN".equals(f.disposition.name())).count());
        result.counts.put("lowConfidenceRecords", all.stream()
                .filter(f -> f.disposition != null
                        && "LOW_CONFIDENCE".equals(f.disposition.name())).count());
        result.counts.put("suppressedRecords", all.stream()
                .filter(f -> f.disposition != null
                        && "SUPPRESSED".equals(f.disposition.name())).count());
        if (parseError) {
            result.evidenceState = EvidenceState.UNKNOWN;
            result.requiresTargetedDiagnosis = true;
            result.vulnerabilityConclusion = "unknown";
            return new QueryOutcome(result, EXIT_UNAVAILABLE);
        }
        if (matched.isEmpty()) {
            result.evidenceState = EvidenceState.NO;
            result.requiresTargetedDiagnosis = true;
            result.vulnerabilityConclusion = "unknown";
            result.notes.add("No matching finding record exists. Zero findings do not prove "
                    + "that no vulnerability exists; run targeted diagnose for a specific "
                    + "sink/source.");
        } else {
            result.evidenceState = EvidenceState.YES;
            result.requiresTargetedDiagnosis = false;
            result.vulnerabilityConclusion = "finding_observed";
        }
        return new QueryOutcome(result, EXIT_OK);
    }

    private QueryOutcome scanStatus(Path workspace) {
        QueryResult result = baseResult(workspace, "scan-status");
        Path workerResultPath = workspace.resolve("worker/single/worker-result.json");
        Path workerRequestPath = workspace.resolve("worker/single/worker-request.json");
        addArtifact(result, workspace, workerResultPath);
        addArtifact(result, workspace, workerRequestPath);
        addArtifact(result, workspace, workspace.resolve("benchmark.json"));
        addArtifact(result, workspace, workspace.resolve("expansion-metrics.json"));
        addArtifact(result, workspace, workspace.resolve("api.txt"));
        addArtifact(result, workspace, workspace.resolve("rules.yaml"));
        addArtifact(result, workspace, workspace.resolve("result.sarif"));
        if (!Files.isRegularFile(workerResultPath)) {
            result.evidenceState = EvidenceState.UNKNOWN;
            result.requiresTargetedDiagnosis = true;
            result.vulnerabilityConclusion = "unknown";
            result.notes.add("No worker-result.json exists. Run '-m scan' or targeted diagnose.");
            return new QueryOutcome(result, EXIT_UNAVAILABLE);
        }
        TaieWorkerResult workerResult;
        TaieWorkerRequest workerRequest = null;
        try {
            workerResult = MAPPER.readValue(workerResultPath.toFile(), TaieWorkerResult.class);
        } catch (Exception e) {
            result.evidenceState = EvidenceState.UNKNOWN;
            result.error = "failed to parse worker-result.json: " + e;
            result.requiresTargetedDiagnosis = true;
            result.vulnerabilityConclusion = "unknown";
            return new QueryOutcome(result, EXIT_UNAVAILABLE);
        }
        if (Files.isRegularFile(workerRequestPath)) {
            try {
                workerRequest = MAPPER.readValue(workerRequestPath.toFile(),
                        TaieWorkerRequest.class);
            } catch (Exception e) {
                result.notes.add("failed to parse worker-request.json: " + e);
            }
        }
        Map<String, Object> worker = new LinkedHashMap<>();
        worker.put("status", workerResult.status);
        worker.put("exitCode", workerResult.exitCode);
        worker.put("worldCompleted", workerResult.worldCompleted);
        worker.put("analysisCompleted", workerResult.analysisCompleted);
        worker.put("totalMs", workerResult.totalMs);
        worker.put("worldMs", workerResult.worldMs);
        worker.put("ptaMs", workerResult.ptaMs);
        worker.put("errorClass", workerResult.errorClass);
        worker.put("errorMessage", workerResult.errorMessage);
        worker.put("taintFlowCount", workerResult.taintFlows == null
                ? 0 : workerResult.taintFlows.size());
        result.worker = worker;

        worker.put("resultPath", workerResultPath.toAbsolutePath().normalize().toString());
        worker.put("requestPath", workerRequestPath.toAbsolutePath().normalize().toString());

        Map<String, Object> benchmarkCounts = readBenchmarkCounts(workspace.resolve("benchmark.json"));
        if (!benchmarkCounts.isEmpty()) {
            result.counts.putAll(benchmarkCounts);
        }
        result.counts.put("taintFlowCount", workerResult.taintFlows == null
                ? 0 : workerResult.taintFlows.size());

        if (!TaieWorkerResult.STATUS_SUCCESS.equals(workerResult.status)) {
            result.evidenceState = EvidenceState.UNKNOWN;
            result.requiresTargetedDiagnosis = true;
            result.vulnerabilityConclusion = "unknown";
            result.notes.add("The scan worker did not complete successfully; downstream "
                    + "evidence is unknown.");
            return new QueryOutcome(result, EXIT_WORKER_FAILED);
        }
        result.evidenceState = EvidenceState.YES;
        result.requiresTargetedDiagnosis = false;
        result.vulnerabilityConclusion = "scan_completed";
        return new QueryOutcome(result, EXIT_OK);
    }

    private void addWorkerSummary(QueryResult result, Path workspace) {
        Path workerResultPath = workspace.resolve("worker/single/worker-result.json");
        if (!Files.isRegularFile(workerResultPath)) {
            result.notes.add("worker-result.json is missing; worker status is unavailable.");
            return;
        }
        try {
            TaieWorkerResult workerResult = MAPPER.readValue(
                    workerResultPath.toFile(), TaieWorkerResult.class);
            result.worker = workerSummary(workerResult);
            if (!TaieWorkerResult.STATUS_SUCCESS.equals(workerResult.status)) {
                result.notes.add("worker-result.json status is " + workerResult.status
                        + "; findings below reflect the existing finding sidecars.");
            }
        } catch (Exception e) {
            result.notes.add("failed to parse worker-result.json: " + e);
        }
    }

    private Map<String, Object> workerSummary(TaieWorkerResult workerResult) {
        Map<String, Object> worker = new LinkedHashMap<>();
        worker.put("status", workerResult.status);
        worker.put("exitCode", workerResult.exitCode);
        worker.put("worldCompleted", workerResult.worldCompleted);
        worker.put("analysisCompleted", workerResult.analysisCompleted);
        worker.put("totalMs", workerResult.totalMs);
        worker.put("worldMs", workerResult.worldMs);
        worker.put("ptaMs", workerResult.ptaMs);
        worker.put("errorClass", workerResult.errorClass);
        worker.put("errorMessage", workerResult.errorMessage);
        worker.put("taintFlowCount", workerResult.taintFlows == null
                ? 0 : workerResult.taintFlows.size());
        return worker;
    }

    private List<Path> sidecarFiles(Path workspace) {
        return List.of(
                workspace.resolve("findings-main.jsonl"),
                workspace.resolve("low-confidence.jsonl"),
                workspace.resolve("results-suppressed.jsonl")
        );
    }

    private QueryResult baseResult(Path workspace, String query) {
        QueryResult result = new QueryResult();
        result.generatedAt = Instant.now().toString();
        result.query = query;
        result.workspace = workspace == null ? null : workspace.toString();
        result.evidenceState = EvidenceState.UNKNOWN;
        result.vulnerabilityConclusion = "unknown";
        return result;
    }

    private void addArtifact(QueryResult result, Path workspace, Path path) {
        Map<String, Object> item = new LinkedHashMap<>();
        Path absolute = path.toAbsolutePath().normalize();
        item.put("path", absolute.toString());
        try {
            item.put("relativePath", workspace == null ? absolute.getFileName().toString()
                    : workspace.toAbsolutePath().normalize().relativize(absolute).toString());
        } catch (Exception ignored) {
            item.put("relativePath", absolute.getFileName().toString());
        }
        item.put("exists", Files.exists(absolute));
        if (Files.exists(absolute)) {
            try {
                item.put("size", Files.size(absolute));
                item.put("lastModified", Files.getLastModifiedTime(absolute).toMillis());
            } catch (Exception ignored) {
                // best effort
            }
        }
        result.artifacts.add(item);
    }

    private Map<String, Object> readBenchmarkCounts(Path benchmark) {
        Map<String, Object> counts = new LinkedHashMap<>();
        if (!Files.isRegularFile(benchmark)) {
            return counts;
        }
        try {
            Map<?, ?> root = MAPPER.readValue(benchmark.toFile(), Map.class);
            Object expansion = root.get("expansion");
            if (expansion instanceof Map<?, ?> map) {
                for (String key : List.of("flowsRaw", "findingsAfterExactDedupe",
                        "findingsAfterFanIn", "mainSarifResults", "lowConfidenceResults",
                        "suppressedResults")) {
                    if (map.containsKey(key)) {
                        counts.put(key, map.get(key));
                    }
                }
            }
        } catch (Exception ignored) {
            // benchmark is optional
        }
        return counts;
    }

    private boolean findingSourceMatches(CanonicalFinding finding, TaiEMethodSignature source,
                                         String sourceIndex) {
        if (finding.instances == null || finding.instances.isEmpty()) {
            return false;
        }
        for (FindingInstance instance : finding.instances) {
            if (!signatureMatches(instance.sourceRuleSignature, source)) {
                continue;
            }
            if (sourceIndex == null || sourceIndex.equals(
                    TaiEMethodSignature.normalizeIndex(instance.sourceIndex))) {
                return true;
            }
        }
        return false;
    }

    private boolean signatureMatches(String raw, TaiEMethodSignature expected) {
        if (raw == null || expected == null) {
            return false;
        }
        TaiEMethodSignature parsed = TaiEMethodSignature.parseNullable(raw);
        return parsed != null && parsed.sameMethod(expected);
    }

    public static String toJson(Object value) throws Exception {
        return OUTPUT.writeValueAsString(value);
    }
}
