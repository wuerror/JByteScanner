package com.jbytescanner.engine;

import com.jbytescanner.config.Config;
import com.jbytescanner.config.ScanConfig;
import com.jbytescanner.config.SourceRule;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CanonicalIdentityTest {

    @TempDir
    Path tempDir;

    @Test
    void dedupeOrderedKeepsFirstSeenAndCountsDuplicates() {
        List<String> raw = List.of(
                "<com.example.C: void a()>",
                "<com.example.C: void b()>",
                "<com.example.C: void a()>",
                "<com.example.C: void a()>",
                "<com.example.C: void b()>"
        );
        CanonicalIdentity.DedupResult result = CanonicalIdentity.dedupeOrdered(raw);
        assertEquals(5, result.raw());
        assertEquals(2, result.unique());
        assertEquals(3, result.duplicate());
        assertEquals(List.of(
                "<com.example.C: void a()>",
                "<com.example.C: void b()>"
        ), result.uniqueItems());
        assertEquals(3, result.topDuplicates().get(0).getValue());
    }

    @Test
    void sourceKeyDistinguishesIndexAndType() {
        String a = CanonicalIdentity.sourceKey("param", "<C: void m(java.lang.String)>", 0, null);
        String b = CanonicalIdentity.sourceKey("param", "<C: void m(java.lang.String)>", 1, null);
        String c = CanonicalIdentity.sourceKey("call", "<C: java.lang.Object get()>", "result", "java.lang.String");
        String d = CanonicalIdentity.sourceKey("call", "<C: java.lang.Object get()>", "result", "java.lang.Integer");
        assertFalse(a.equals(b));
        assertFalse(c.equals(d));

        CanonicalIdentity.SourceCanonicalizer canon = new CanonicalIdentity.SourceCanonicalizer();
        assertTrue(canon.add("param", "<C: void m(java.lang.String)>", 0, null));
        assertFalse(canon.add("param", "<C: void m(java.lang.String)>", 0, null));
        assertTrue(canon.add("param", "<C: void m(java.lang.String)>", 1, null));
        assertEquals(3, canon.raw());
        assertEquals(2, canon.unique());
        assertEquals(1, canon.duplicate());
    }

    @Test
    void generateTaieConfigDedupsDuplicateEntrySourcesAndKeepsDistinctIndexes() throws Exception {
        Config config = new Config();
        config.setScanConfig(new ScanConfig());
        config.setSources(new ArrayList<>());
        config.setSinks(new ArrayList<>());
        config.setTransfers(new ArrayList<>());
        // Disable persistent scan for this unit test (no app jars needed).
        config.getScanConfig().setPersistentSourceAnalysis(false);

        SourceRule explicit = new SourceRule();
        explicit.setType("method");
        explicit.setSignature("<com.example.Lib: java.lang.String read()>");
        explicit.setIndex("result");
        config.getSources().add(explicit);
        // Exact duplicate explicit source should collapse.
        SourceRule explicitDup = new SourceRule();
        explicitDup.setType("method");
        explicitDup.setSignature("<com.example.Lib: java.lang.String read()>");
        explicitDup.setIndex("result");
        config.getSources().add(explicitDup);

        // Same method, different overload signatures remain distinct entry points.
        List<String> entries = List.of(
                "<com.example.Controller: void handle(com.example.Bean)>",
                "<com.example.Controller: void handle(com.example.Bean)>",
                "<com.example.Controller: void handle(java.lang.String)>",
                "<com.example.Controller: void handle(java.lang.String,int)>"
        );
        CanonicalIdentity.DedupResult entryDedup = CanonicalIdentity.dedupeOrdered(entries);
        assertEquals(4, entryDedup.raw());
        assertEquals(3, entryDedup.unique());
        assertEquals(1, entryDedup.duplicate());

        Path workspace = tempDir.resolve("ws");
        Files.createDirectories(workspace);
        String generated = new RuleManager(config)
                .generateTaieConfig(entryDedup.uniqueItems(), workspace.toFile(), List.of());

        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        Map<String, Object> document = mapper.readValue(Path.of(generated).toFile(), new TypeReference<>() {});
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> sources = (List<Map<String, Object>>) document.get("sources");

        Set<String> keys = new java.util.HashSet<>();
        int paramSources = 0;
        int callSources = 0;
        for (Map<String, Object> source : sources) {
            String key = CanonicalIdentity.sourceKey(
                    String.valueOf(source.get("kind")),
                    String.valueOf(source.get("method")),
                    source.get("index"),
                    source.get("type") == null ? null : String.valueOf(source.get("type")));
            assertTrue(keys.add(key), "duplicate source emitted: " + key);
            if ("param".equals(source.get("kind"))) {
                paramSources++;
            } else if ("call".equals(source.get("kind"))) {
                callSources++;
            }
        }

        // handle(Bean)=1, handle(String)=1, handle(String,int)=2 => 4 unique param sources
        assertEquals(4, paramSources);
        // one unique explicit call source after duplicate collapse
        assertEquals(1, callSources);
        assertEquals(5, sources.size());
    }

    @Test
    void differentSourceIndexesRemainDistinct() {
        Map<String, Object> s0 = source("param", "<C: void m(java.lang.String,java.lang.String)>", 0, null);
        Map<String, Object> s1 = source("param", "<C: void m(java.lang.String,java.lang.String)>", 1, null);
        String k0 = CanonicalIdentity.sourceKey(
                String.valueOf(s0.get("kind")), String.valueOf(s0.get("method")), s0.get("index"), null);
        String k1 = CanonicalIdentity.sourceKey(
                String.valueOf(s1.get("kind")), String.valueOf(s1.get("method")), s1.get("index"), null);
        assertFalse(k0.equals(k1));
    }

    @Test
    void integerAndStringIndexAreEquivalentSourceKeys() {
        String fromInt = CanonicalIdentity.sourceKey("param", "<C: void m(java.lang.String)>", 0, null);
        String fromString = CanonicalIdentity.sourceKey("param", "<C: void m(java.lang.String)>", "0", null);
        assertEquals(fromInt, fromString);

        CanonicalIdentity.SourceCanonicalizer canon = new CanonicalIdentity.SourceCanonicalizer();
        assertTrue(canon.add("param", "<C: void m(java.lang.String)>", 0, null));
        assertFalse(canon.add("param", "<C: void m(java.lang.String)>", "0", null));
        assertEquals(1, canon.unique());
        assertEquals(1, canon.duplicate());
    }

    @Test
    void blankAndNullTaintTypeAreEquivalent() {
        String a = CanonicalIdentity.sourceKey("call", "<C: java.lang.Object get()>", "result", null);
        String b = CanonicalIdentity.sourceKey("call", "<C: java.lang.Object get()>", "result", "  ");
        assertEquals(a, b);
    }

    @Test
    void generateTaieConfigDedupsUndedupedEntryListInternally() throws Exception {
        Config config = new Config();
        config.setScanConfig(new ScanConfig());
        config.setSources(new ArrayList<>());
        config.setSinks(new ArrayList<>());
        config.setTransfers(new ArrayList<>());
        config.getScanConfig().setPersistentSourceAnalysis(false);

        // Intentionally pass duplicates; generateTaieConfig must canonicalize.
        List<String> undeduped = List.of(
                "<com.example.Controller: void handle(java.lang.String)>",
                "<com.example.Controller: void handle(java.lang.String)>",
                "<com.example.Controller: void handle(java.lang.String)>"
        );
        Path workspace = tempDir.resolve("ws-undedup");
        Files.createDirectories(workspace);
        String generated = new RuleManager(config)
                .generateTaieConfig(undeduped, workspace.toFile(), List.of());

        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        Map<String, Object> document = mapper.readValue(Path.of(generated).toFile(), new TypeReference<>() {});
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> sources = (List<Map<String, Object>>) document.get("sources");
        assertEquals(1, sources.size());
        assertEquals(0, Integer.parseInt(String.valueOf(sources.get(0).get("index"))));
    }

    private static Map<String, Object> source(String kind, String method, Object index, String type) {
        Map<String, Object> map = new HashMap<>();
        map.put("kind", kind);
        map.put("method", method);
        map.put("index", index);
        if (type != null) {
            map.put("type", type);
        }
        return map;
    }
}
