package com.jbytescanner.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.model.Vulnerability;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
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
        assertTrue(Files.isRegularFile(byType.resolve("SQL_Injection.txt")));
        assertTrue(Files.isRegularFile(byType.resolve("SSRF.txt")));

        JsonNode ssrfDoc = mapper.readTree(byType.resolve("SSRF.sarif").toFile());
        assertEquals(2, ssrfDoc.path("runs").get(0).path("results").size());
        JsonNode sqlDoc = mapper.readTree(byType.resolve("SQL_Injection.sarif").toFile());
        assertEquals(1, sqlDoc.path("runs").get(0).path("results").size());
    }

    @Test
    void writesCallChainTxtGroupedBySink() throws Exception {
        String sink = "<com.example.Http: java.net.URLConnection openConnection()>";
        Vulnerability a = vuln("SSRF",
                "<com.app.A: void handle()>",
                sink,
                List.of(
                        "<com.app.A: void handle()> (Source)",
                        "<com.app.A: void handle()> (Container)",
                        sink + " (Sink)"));
        Vulnerability b = vuln("SSRF",
                "<com.app.B: void fetch()>",
                sink,
                List.of(
                        "<com.app.B: void fetch()> (Source)",
                        sink + " (Sink)"));
        Vulnerability other = vuln("SSRF",
                "<com.app.C: void x()>",
                "<com.example.Other: void sink()>",
                List.of("<com.app.C: void x()> (Source)", "<com.example.Other: void sink()> (Sink)"));

        new SarifReporter(tempDir.toFile()).generate(List.of(a, b, other));

        String txt = Files.readString(tempDir.resolve(SarifReporter.BY_TYPE_DIR).resolve("SSRF.txt"),
                StandardCharsets.UTF_8);

        assertTrue(txt.contains("Sink: " + sink));
        assertTrue(txt.contains("Total chains: 2"));
        assertTrue(txt.contains("Chain #1:"));
        assertTrue(txt.contains("Chain #2:"));
        // sink-first layout for chain A (container collapsed with identical source)
        assertTrue(txt.contains(
                "Chain #1:\n"
                        + sink + "\n"
                        + "    <com.app.A: void handle()>\n"));
        assertTrue(txt.contains(
                "Chain #2:\n"
                        + sink + "\n"
                        + "    <com.app.B: void fetch()>\n"));
        assertTrue(txt.contains("Sink: <com.example.Other: void sink()>"));
        assertTrue(txt.contains("Total chains: 1"));
        assertTrue(!txt.contains("(Source)") && !txt.contains("(Sink)"));
    }

    @Test
    void multiSourcePipelineTraceExpandsToSiblingChains() throws Exception {
        String sink = "<groovy.lang.GroovyShell: java.lang.Object evaluate(java.lang.String)>";
        String container = "<com.app.ScriptRunner: void run(java.lang.String)> @L42 stmt#7";
        Vulnerability aggregated = vuln("Groovy_Injection",
                "<com.app.A: void entry()>",
                sink,
                List.of(
                        "<com.app.A: void entry()> idx=0 route=GET /a (Source/representative)",
                        "<com.app.B: void entry()> idx=1 route=POST /b (Source/instance)",
                        "<com.app.C: void entry()> idx=2 (Source/instance)",
                        "sourceCount=12 shown=3 (full instances in findings-main.jsonl)",
                        container + " (Container)",
                        "localSideEffects=[openStream]",
                        sink + " (Sink)"));

        new SarifReporter(tempDir.toFile()).generate(List.of(aggregated));

        String txt = Files.readString(
                tempDir.resolve(SarifReporter.BY_TYPE_DIR).resolve("Groovy_Injection.txt"),
                StandardCharsets.UTF_8);

        assertTrue(txt.contains("Sink: " + sink));
        // 3 source instances → 3 sibling chains, not one nested stack of sources
        assertTrue(txt.contains("Total chains: 3"));
        assertTrue(txt.contains(
                "Chain #1:\n"
                        + sink + "\n"
                        + "    " + container + "\n"
                        + "        <com.app.A: void entry()> idx=0 route=GET /a\n"));
        assertTrue(txt.contains(
                "Chain #2:\n"
                        + sink + "\n"
                        + "    " + container + "\n"
                        + "        <com.app.B: void entry()> idx=1 route=POST /b\n"));
        assertTrue(txt.contains(
                "Chain #3:\n"
                        + sink + "\n"
                        + "    " + container + "\n"
                        + "        <com.app.C: void entry()> idx=2\n"
                        + "    sourceCount=12 shown=3 (full instances in findings-main.jsonl)\n"
                        + "    localSideEffects=[openStream]\n"));
        // Must not nest sources as a fake call stack
        assertTrue(!txt.contains(
                "        <com.app.C: void entry()> idx=2\n"
                        + "            <com.app.B: void entry()>"));
    }

    @Test
    void cleanTraceStepStripsRoleTags() {
        assertEquals("<a: void m()>",
                SarifReporter.cleanTraceStep("<a: void m()> (Source/representative)"));
        assertEquals("<b: void n()>",
                SarifReporter.cleanTraceStep("<b: void n()> (Sink)"));
        assertEquals(null, SarifReporter.cleanTraceStep("sourceCount=12 shown=10 (full instances in findings-main.jsonl)"));
    }

    @Test
    void sanitizeFileNameStripsInvalidChars() {
        assertEquals("Groovy_Injection", SarifReporter.sanitizeFileName("Groovy_Injection"));
        assertEquals("A_B", SarifReporter.sanitizeFileName("A/B"));
        assertEquals("Unknown", SarifReporter.sanitizeFileName("  "));
    }

    private static Vulnerability vuln(String type, String src, String sink) {
        return vuln(type, src, sink, List.of(src, sink));
    }

    private static Vulnerability vuln(String type, String src, String sink, List<String> trace) {
        SinkRule rule = new SinkRule();
        rule.setVulnType(type);
        rule.setSignature("<x: void y()>");
        Vulnerability v = new Vulnerability(type, src, sink, trace, true, rule);
        v.setScore(5.0);
        v.setConfidenceScore(0.8);
        v.setRiskLevel("MEDIUM");
        return v;
    }
}
