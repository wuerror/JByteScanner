package com.jbytescanner.finding;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.jbytescanner.config.NoiseFilterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

public final class FindingSidecarWriter {

    private static final Logger logger = LoggerFactory.getLogger(FindingSidecarWriter.class);
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .disable(SerializationFeature.INDENT_OUTPUT);

    private FindingSidecarWriter() {
    }

    public static void write(File workspaceDir, PipelineResult result, NoiseFilterConfig cfg,
                             List<?> rawFlows) {
        if (workspaceDir == null || result == null || cfg == null) {
            return;
        }
        try {
            if (cfg.isEmitSuppressedFile()) {
                writeJsonl(new File(workspaceDir, "results-suppressed.jsonl"),
                        result.suppressedFindings);
            }
            if (cfg.isEmitLowConfidenceFile()) {
                writeJsonl(new File(workspaceDir, "low-confidence.jsonl"),
                        result.lowConfidenceFindings);
            }
            if (cfg.isEmitRawFlows() && rawFlows != null) {
                writeJsonl(new File(workspaceDir, "raw-flows.jsonl"), rawFlows);
            }
            // Always emit full instance dump for main findings (sidecar for fan-in).
            writeJsonl(new File(workspaceDir, "findings-main.jsonl"), result.mainFindings);
        } catch (Exception e) {
            logger.warn("Failed to write finding sidecars: {}", e.toString());
        }
    }

    private static void writeJsonl(File file, List<?> items) throws Exception {
        if (items == null) {
            return;
        }
        try (BufferedWriter w = Files.newBufferedWriter(file.toPath(), StandardCharsets.UTF_8)) {
            for (Object item : items) {
                w.write(MAPPER.writeValueAsString(item));
                w.newLine();
            }
        }
        logger.info("Wrote {} ({} line(s))", file.getName(), items.size());
    }
}
