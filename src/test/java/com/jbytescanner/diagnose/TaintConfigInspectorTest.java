package com.jbytescanner.diagnose;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TaintConfigInspectorTest {

    @TempDir
    Path tempDir;

    @Test
    void readsExactSinkAndSourceRules() throws Exception {
        Path config = tempDir.resolve("taint-config.yml");
        Files.writeString(config, """
                call-site-mode: true
                sources:
                  - kind: param
                    method: "<com.example.Controller: void run(java.lang.String)>"
                    index: 0
                  - kind: call
                    method: "<com.example.Source: java.lang.String get(java.lang.String)>"
                    index: result
                sinks:
                  - method: "<java.io.File: void <init>(java.lang.String)>"
                    index: 0
                  - method: "<java.io.File: void <init>(java.lang.String,java.lang.String)>"
                    index: 0
                transfers: []
                """);

        TaintConfigInspector.EmittedConfig emitted = TaintConfigInspector.read(config);

        assertTrue(emitted.errors().isEmpty());
        assertTrue(emitted.hasSink("<java.io.File: void <init>(java.lang.String)>", "0"));
        assertFalse(emitted.hasSink("<java.io.File: void <init>(java.lang.String)>", "1"));
        assertFalse(emitted.hasSink(
                "<java.io.File: void <init>(java.lang.String,java.lang.String)>", "1"));
        assertTrue(emitted.hasSource(
                "<com.example.Controller: void run(java.lang.String)>", "0"));
        assertTrue(emitted.hasSource(
                "<com.example.Source: java.lang.String get(java.lang.String)>", "result"));
        assertFalse(emitted.hasSource(
                "<com.example.Controller: void run(java.lang.String)>", "1"));
        assertTrue(emitted.sourcesFor(
                "<com.example.Controller: void run(java.lang.String)>").size() == 1);
    }

    @Test
    void reportsPartialShardReadsButRetainsObservedRules() throws Exception {
        Path directory = tempDir.resolve("partial-config.d");
        Files.createDirectories(directory);
        Files.writeString(directory.resolve("000-sinks.yml"), """
                sinks:
                  - method: "<java.io.File: void <init>(java.lang.String)>"
                    index: 0
                """);
        Files.writeString(directory.resolve("999-broken.yml"),
                "sinks:\n  - method: \"<unterminated\n");

        TaintConfigInspector.EmittedConfig emitted = TaintConfigInspector.read(directory);

        assertFalse(emitted.errors().isEmpty());
        assertTrue(emitted.hasSink(
                "<java.io.File: void <init>(java.lang.String)>", "0"));
    }

    @Test
    void readsShardedConfigDirectory() throws Exception {
        Path directory = tempDir.resolve("taint-config.d");
        Files.createDirectories(directory);
        Files.writeString(directory.resolve("000-options.yml"), "call-site-mode: true\n");
        Files.writeString(directory.resolve("001-sources.yml"), """
                sources:
                  - kind: param
                    method: "<com.example.Controller: void run(java.lang.String)>"
                    index: 0
                """);
        Files.writeString(directory.resolve("002-sinks.yml"), """
                sinks:
                  - method: "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>"
                    index: 0
                """);

        TaintConfigInspector.EmittedConfig emitted = TaintConfigInspector.read(directory);

        assertTrue(emitted.hasSink(
                "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>", "0"));
        assertTrue(emitted.hasSource(
                "<com.example.Controller: void run(java.lang.String)>", "0"));
        assertTrue(emitted.sinks().size() == 1);
        assertTrue(emitted.sources().size() == 1);
    }
}
