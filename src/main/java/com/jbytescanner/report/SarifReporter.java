package com.jbytescanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.jbytescanner.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Writes SARIF 2.1 reports. Always emits the combined {@code result.sarif},
 * and additionally one file per {@code vuln_type} (e.g. {@code SSRF.sarif})
 * plus a plain-text call-chain companion (e.g. {@code SSRF.txt}) for offline review.
 */
public class SarifReporter {
    private static final Logger logger = LoggerFactory.getLogger(SarifReporter.class);

    /** Subdirectory under workspace for per-type SARIF files. */
    public static final String BY_TYPE_DIR = "sarif-by-type";

    private final File workspaceDir;

    public SarifReporter(File workspaceDir) {
        this.workspaceDir = workspaceDir;
    }

    public void generate(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities == null) {
            vulnerabilities = List.of();
        }

        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        // 1) Combined report (compatibility)
        writeSarif(mapper, new File(workspaceDir, "result.sarif"), vulnerabilities);

        // 2) Split by vuln_type: SARIF + human-readable call-chain TXT
        Map<String, List<Vulnerability>> byType = groupByType(vulnerabilities);
        File typeDir = new File(workspaceDir, BY_TYPE_DIR);
        if (!typeDir.exists() && !typeDir.mkdirs()) {
            logger.warn("Could not create {}: {}", BY_TYPE_DIR, typeDir.getAbsolutePath());
            return;
        }

        int files = 0;
        for (Map.Entry<String, List<Vulnerability>> e : byType.entrySet()) {
            String base = sanitizeFileName(e.getKey());
            writeSarif(mapper, new File(typeDir, base + ".sarif"), e.getValue());
            writeCallChainTxt(new File(typeDir, base + ".txt"), e.getValue());
            files++;
        }
        logger.info("SARIF split by vuln_type: {} file(s) (+txt chains) under {}",
                files, typeDir.getAbsolutePath());
    }

    static Map<String, List<Vulnerability>> groupByType(List<Vulnerability> vulnerabilities) {
        Map<String, List<Vulnerability>> byType = new LinkedHashMap<>();
        for (Vulnerability v : vulnerabilities) {
            String type = v.getType();
            if (type == null || type.isBlank()) {
                type = "Unknown";
            }
            byType.computeIfAbsent(type, ignored -> new ArrayList<>()).add(v);
        }
        return byType;
    }

    /**
     * Windows-safe file base name from vuln_type.
     */
    static String sanitizeFileName(String vulnType) {
        if (vulnType == null || vulnType.isBlank()) {
            return "Unknown";
        }
        String s = vulnType.trim()
                .replaceAll("[\\\\/:*?\"<>|]", "_")
                .replaceAll("\\s+", "_");
        if (s.isBlank()) {
            return "Unknown";
        }
        // Avoid reserved device names on Windows
        if (s.matches("(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])")) {
            s = "_" + s;
        }
        return s;
    }

    private void writeSarif(ObjectMapper mapper, File outFile, List<Vulnerability> vulnerabilities) {
        ObjectNode root = mapper.createObjectNode();
        root.put("version", "2.1.0");
        root.put("$schema", "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json");

        ArrayNode runs = root.putArray("runs");
        ObjectNode run = runs.addObject();

        ObjectNode tool = run.putObject("tool");
        ObjectNode driver = tool.putObject("driver");
        driver.put("name", "JByteScanner");
        driver.put("version", "1.0");

        ArrayNode results = run.putArray("results");
        for (Vulnerability v : vulnerabilities) {
            appendResult(results, v);
        }

        try {
            mapper.writeValue(outFile, root);
            logger.info("SARIF Report generated: {} ({} result(s))",
                    outFile.getAbsolutePath(), vulnerabilities.size());
        } catch (IOException e) {
            logger.error("Failed to write SARIF report: {}", outFile, e);
        }
    }

    /**
     * Human-readable call chains grouped by sink, for offline code review without SARIF tooling.
     *
     * <p>Pipeline findings may pack multiple source <em>instances</em> into one Vulnerability;
     * each instance is expanded to its own chain (siblings under the same sink), not nested
     * as if they called each other.</p>
     *
     * <pre>
     * Sink: &lt;sinkMethod&gt;
     * Total chains: N
     * ================================================================================
     *
     * Chain #1:
     * sinkMethod
     *     containerMethod
     *         sourceMethod
     * </pre>
     */
    static void writeCallChainTxt(File outFile, List<Vulnerability> vulnerabilities) {
        if (outFile == null) {
            return;
        }
        if (vulnerabilities == null) {
            vulnerabilities = List.of();
        }

        Map<String, List<Vulnerability>> bySink = groupBySink(vulnerabilities);
        StringBuilder sb = new StringBuilder();

        boolean firstSink = true;
        for (Map.Entry<String, List<Vulnerability>> e : bySink.entrySet()) {
            if (!firstSink) {
                sb.append('\n');
            }
            firstSink = false;

            String sink = e.getKey();
            List<ParsedChain> chains = new ArrayList<>();
            for (Vulnerability v : e.getValue()) {
                chains.addAll(expandChains(v));
            }

            sb.append("Sink: ").append(sink).append('\n');
            sb.append("Total chains: ").append(chains.size()).append('\n');
            sb.append("================================================================================\n");

            int idx = 1;
            for (ParsedChain chain : chains) {
                sb.append('\n');
                sb.append("Chain #").append(idx++).append(":\n");
                appendIndentedChain(sb, chain);
            }
            sb.append('\n');
        }

        try (BufferedWriter w = Files.newBufferedWriter(outFile.toPath(), StandardCharsets.UTF_8)) {
            w.write(sb.toString());
            logger.info("Call-chain TXT generated: {} ({} finding(s))",
                    outFile.getAbsolutePath(), vulnerabilities.size());
        } catch (IOException ex) {
            logger.error("Failed to write call-chain TXT: {}", outFile, ex);
        }
    }

    static Map<String, List<Vulnerability>> groupBySink(List<Vulnerability> vulnerabilities) {
        Map<String, List<Vulnerability>> bySink = new LinkedHashMap<>();
        for (Vulnerability v : vulnerabilities) {
            String sink = v.getSinkMethod();
            if (sink == null || sink.isBlank()) {
                sink = "<unknown-sink>";
            }
            bySink.computeIfAbsent(sink, ignored -> new ArrayList<>()).add(v);
        }
        return bySink;
    }

    /**
     * Expand one Vulnerability into one-or-more display chains.
     * Multi-source pipeline traces become sibling chains (one per source), not a nested stack.
     */
    static List<ParsedChain> expandChains(Vulnerability v) {
        ParsedTrace parsed = parseTrace(v);
        List<ParsedChain> out = new ArrayList<>();
        if (parsed.sources.isEmpty()) {
            out.add(new ParsedChain(parsed.sink, parsed.container, null, parsed.notes));
            return out;
        }
        for (int i = 0; i < parsed.sources.size(); i++) {
            // Attach notes only once (on the last expanded chain) so multi-source
            // findings still surface sourceCount / side-effect meta.
            List<String> notes = (i == parsed.sources.size() - 1) ? parsed.notes : List.of();
            out.add(new ParsedChain(parsed.sink, parsed.container, parsed.sources.get(i), notes));
        }
        return out;
    }

    /** Emit sink → optional container → source, with optional trailing notes. */
    static void appendIndentedChain(StringBuilder sb, ParsedChain chain) {
        int depth = 0;
        sb.append("    ".repeat(depth)).append(chain.sink).append('\n');
        depth++;
        if (chain.container != null && !chain.container.isBlank()
                && !chain.container.equals(chain.sink)) {
            sb.append("    ".repeat(depth)).append(chain.container).append('\n');
            depth++;
        }
        if (chain.source != null && !chain.source.isBlank()
                && !chain.source.equals(chain.sink)
                && !chain.source.equals(chain.container)) {
            sb.append("    ".repeat(depth)).append(chain.source).append('\n');
        }
        if (chain.notes != null) {
            for (String note : chain.notes) {
                sb.append("    ").append(note).append('\n');
            }
        }
    }

    static ParsedTrace parseTrace(Vulnerability v) {
        List<String> sources = new ArrayList<>();
        String container = null;
        String sink = null;
        List<String> notes = new ArrayList<>();

        if (v.getTrace() != null) {
            for (String raw : v.getTrace()) {
                if (raw == null) {
                    continue;
                }
                String step = raw.trim();
                if (step.isEmpty()) {
                    continue;
                }
                if (step.startsWith("sourceCount=") || step.startsWith("localSideEffects=")) {
                    notes.add(step);
                    continue;
                }
                Role role = detectRole(step);
                String cleaned = stripRoleTag(step);
                if (cleaned == null || cleaned.isBlank()) {
                    continue;
                }
                switch (role) {
                    case SOURCE -> {
                        if (sources.isEmpty() || !cleaned.equals(sources.get(sources.size() - 1))) {
                            sources.add(cleaned);
                        }
                    }
                    case CONTAINER -> container = cleaned;
                    case SINK -> sink = cleaned;
                    case UNKNOWN -> {
                        // Legacy / untagged steps: treat as ordered path pieces (source-side first).
                        sources.add(cleaned);
                    }
                }
            }
        }

        if (sink == null || sink.isBlank()) {
            sink = v.getSinkMethod() != null && !v.getSinkMethod().isBlank()
                    ? v.getSinkMethod() : "<unknown-sink>";
        }
        // Untagged multi-step traces: last piece is sink, earlier pieces are path (single chain).
        if (sources.size() >= 2 && detectRole(
                v.getTrace() != null && !v.getTrace().isEmpty()
                        ? v.getTrace().get(v.getTrace().size() - 1) : "") == Role.UNKNOWN) {
            String last = sources.remove(sources.size() - 1);
            if (sink.equals("<unknown-sink>") || sink.equals(last)) {
                sink = last;
            }
            // Collapse path intermediates: keep first as source, middle as container if only one middle.
            if (sources.size() >= 2 && container == null) {
                container = sources.remove(sources.size() - 1);
                // Keep only the entry source for untagged linear path
                String entry = sources.get(0);
                sources.clear();
                sources.add(entry);
            } else if (sources.size() > 1 && container == null) {
                // multiple untagged: keep as sources only if they look like instances; else first+last
                String entry = sources.get(0);
                sources.clear();
                sources.add(entry);
            }
        }
        if (sources.isEmpty() && v.getSourceMethod() != null && !v.getSourceMethod().isBlank()) {
            sources.add(v.getSourceMethod());
        }
        return new ParsedTrace(sources, container, sink, notes);
    }

    static Role detectRole(String step) {
        if (step == null) {
            return Role.UNKNOWN;
        }
        if (step.matches(".*\\(Source(?:/representative|/instance)?\\)\\s*$")) {
            return Role.SOURCE;
        }
        if (step.matches(".*\\(Container\\)\\s*$")) {
            return Role.CONTAINER;
        }
        if (step.matches(".*\\(Sink\\)\\s*$")) {
            return Role.SINK;
        }
        return Role.UNKNOWN;
    }

    /** Strip trailing role tags like {@code (Source)} / {@code (Sink)} for compact review text. */
    static String cleanTraceStep(String step) {
        if (step == null) {
            return null;
        }
        String s = step.trim();
        if (s.startsWith("sourceCount=") || s.startsWith("localSideEffects=")) {
            return null;
        }
        return stripRoleTag(s);
    }

    static String stripRoleTag(String step) {
        if (step == null) {
            return null;
        }
        return step.trim()
                .replaceAll("\\s*\\((Source(?:/representative|/instance)?|Container|Sink)\\)\\s*$", "")
                .trim();
    }

    enum Role {
        SOURCE, CONTAINER, SINK, UNKNOWN
    }

    /** One display chain: sink → container? → source?, plus optional notes. */
    static final class ParsedChain {
        final String sink;
        final String container;
        final String source;
        final List<String> notes;

        ParsedChain(String sink, String container, String source, List<String> notes) {
            this.sink = sink;
            this.container = container;
            this.source = source;
            this.notes = notes != null ? notes : List.of();
        }
    }

    static final class ParsedTrace {
        final List<String> sources;
        final String container;
        final String sink;
        final List<String> notes;

        ParsedTrace(List<String> sources, String container, String sink, List<String> notes) {
            this.sources = sources != null ? sources : List.of();
            this.container = container;
            this.sink = sink;
            this.notes = notes != null ? notes : List.of();
        }
    }

    private static void appendResult(ArrayNode results, Vulnerability v) {
        ObjectNode result = results.addObject();
        result.put("ruleId", v.getType());
        String sarifLevel = "warning";
        if ("CRITICAL".equals(v.getRiskLevel()) || "HIGH".equals(v.getRiskLevel())) {
            sarifLevel = "error";
        } else if ("INFO".equals(v.getRiskLevel())) {
            sarifLevel = "note";
        }
        result.put("level", sarifLevel);

        ObjectNode message = result.putObject("message");
        String risk = v.getRiskLevel() != null ? v.getRiskLevel() : "UNKNOWN";
        String scoreStr = String.format("%.1f", v.getScore());
        message.put("text", String.format("[%s] Score: %s | %s flow from %s to %s",
                risk, scoreStr, v.getType(), v.getSourceMethod(), v.getSinkMethod()));

        ObjectNode properties = result.putObject("properties");
        properties.put("score", v.getScore());
        properties.put("confidence", v.getConfidenceScore());
        properties.put("riskLevel", v.getRiskLevel());
        if (v.getSeverityScore() > 0) {
            properties.put("severityScore", v.getSeverityScore());
        }
        if (v.getRankScore() > 0) {
            properties.put("rankScore", v.getRankScore());
        }
        if (v.getSinkStrength() != null) {
            properties.put("sinkStrength", v.getSinkStrength());
        }
        if (v.getEvidenceLevel() != null) {
            properties.put("evidenceLevel", v.getEvidenceLevel());
        }
        if (v.getSinkContainerSignature() != null) {
            properties.put("sinkContainer", v.getSinkContainerSignature());
        }
        if (v.getSinkStmtIndex() >= 0) {
            properties.put("sinkStmtIndex", v.getSinkStmtIndex());
        }
        if (v.getSinkIndex() != null) {
            properties.put("sinkIndex", v.getSinkIndex());
        }
        if (v.getSourceIndex() != null) {
            properties.put("sourceIndex", v.getSourceIndex());
        }
        if (v.getSourceCount() > 0) {
            properties.put("sourceCount", v.getSourceCount());
        }
        if (v.getPackageProvenance() != null) {
            properties.put("packageProvenance", v.getPackageProvenance());
        }
        if (v.getReasonCodes() != null && !v.getReasonCodes().isEmpty()) {
            ArrayNode reasons = properties.putArray("reasonCodes");
            for (String r : v.getReasonCodes()) {
                reasons.add(r);
            }
        }

        ArrayNode locations = result.putArray("locations");
        ObjectNode location = locations.addObject();
        ObjectNode physicalLocation = location.putObject("physicalLocation");
        ObjectNode artifactLocation = physicalLocation.putObject("artifactLocation");
        String uri = v.getSinkContainerSignature() != null
                ? v.getSinkContainerSignature()
                : v.getSinkMethod();
        artifactLocation.put("uri", uri);

        ArrayNode codeFlows = result.putArray("codeFlows");
        ObjectNode codeFlow = codeFlows.addObject();
        ArrayNode threadFlows = codeFlow.putArray("threadFlows");
        ObjectNode threadFlow = threadFlows.addObject();
        ArrayNode locationsFlow = threadFlow.putArray("locations");

        if (v.getTrace() != null) {
            for (String step : v.getTrace()) {
                ObjectNode loc = locationsFlow.addObject();
                ObjectNode stepLoc = loc.putObject("location");
                ObjectNode stepMsg = stepLoc.putObject("message");
                stepMsg.put("text", step);
            }
        }
    }
}
