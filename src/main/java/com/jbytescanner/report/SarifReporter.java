package com.jbytescanner.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.jbytescanner.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Writes SARIF 2.1 reports. Always emits the combined {@code result.sarif},
 * and additionally one file per {@code vuln_type} (e.g. {@code SSRF.sarif}).
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

        // 2) Split by vuln_type
        Map<String, List<Vulnerability>> byType = groupByType(vulnerabilities);
        File typeDir = new File(workspaceDir, BY_TYPE_DIR);
        if (!typeDir.exists() && !typeDir.mkdirs()) {
            logger.warn("Could not create {}: {}", BY_TYPE_DIR, typeDir.getAbsolutePath());
            return;
        }

        int files = 0;
        for (Map.Entry<String, List<Vulnerability>> e : byType.entrySet()) {
            String fileName = sanitizeFileName(e.getKey()) + ".sarif";
            File out = new File(typeDir, fileName);
            writeSarif(mapper, out, e.getValue());
            files++;
        }
        logger.info("SARIF split by vuln_type: {} file(s) under {}",
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
