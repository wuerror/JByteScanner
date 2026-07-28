package com.jbytescanner.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.model.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SarifReporterTest {

    @TempDir
    Path tempDir;

    @Test
    void writesCombinedAndPerTypeSarif() throws Exception {
        Vulnerability sql = vuln("SQL_Injection", "srcA", "sinkA");
        Vulnerability ssrf = vuln("SSRF", "srcB", "sinkB");
        Vulnerability ssrf2 = vuln("SSRF", "srcC", "sinkC");

        new SarifReporter(tempDir.toFile()).generate(List.of(sql, ssrf, ssrf2));

        Path combined = tempDir.resolve("result.sarif");
        assertTrue(Files.isRegularFile(combined));
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(combined.toFile());
        assertEquals(3, root.path("runs").get(0).path("results").size());

        Path byType = tempDir.resolve(SarifReporter.BY_TYPE_DIR);
        assertTrue(Files.isDirectory(byType));
        assertTrue(Files.isRegularFile(byType.resolve("SQL_Injection.sarif")));
        assertTrue(Files.isRegularFile(byType.resolve("SSRF.sarif")));

        JsonNode ssrfDoc = mapper.readTree(byType.resolve("SSRF.sarif").toFile());
        assertEquals(2, ssrfDoc.path("runs").get(0).path("results").size());
        JsonNode sqlDoc = mapper.readTree(byType.resolve("SQL_Injection.sarif").toFile());
        assertEquals(1, sqlDoc.path("runs").get(0).path("results").size());
    }

    @Test
    void sanitizeFileNameStripsInvalidChars() {
        assertEquals("Groovy_Injection", SarifReporter.sanitizeFileName("Groovy_Injection"));
        assertEquals("A_B", SarifReporter.sanitizeFileName("A/B"));
        assertEquals("Unknown", SarifReporter.sanitizeFileName("  "));
    }

    private static Vulnerability vuln(String type, String src, String sink) {
        SinkRule rule = new SinkRule();
        rule.setVulnType(type);
        rule.setSignature("<x: void y()>");
        Vulnerability v = new Vulnerability(type, src, sink, List.of(src, sink), true, rule);
        v.setScore(5.0);
        v.setConfidenceScore(0.8);
        v.setRiskLevel("MEDIUM");
        return v;
    }
}
