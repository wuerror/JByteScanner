package com.jbytescanner.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigManagerMigrationTest {

    @TempDir
    Path tempDir;

    @Test
    void migratesLegacyRulesWithoutOverwritingUserOverrides() throws Exception {
        Path rules = tempDir.resolve("rules.yaml");
        Files.writeString(rules, """
                config:
                  max_depth: 7
                  scan_packages: ["com.example"]
                sources: []
                sinks:
                  - type: method
                    vuln_type: CustomDeserialization
                    category: custom-category
                    signature: "<java.io.ObjectInputStream: java.lang.Object readObject()>"
                  - type: method
                    vuln_type: Custom
                    category: custom
                    signature: "<example.Sink: void consume(java.lang.String)>"
                """, StandardCharsets.UTF_8);

        ConfigManager manager = new ConfigManager();
        manager.init(tempDir.toFile());
        Config migrated = manager.getConfig();

        assertEquals(3, migrated.getRulesVersion());
        assertEquals(7, migrated.getScanConfig().getMaxDepth());
        assertEquals("com.example", migrated.getScanConfig().getScanPackages().get(0));
        assertTrue(Files.exists(tempDir.resolve("rules.yaml.bak-v0")));

        SinkRule nativeDeser = findSink(migrated,
                "<java.io.ObjectInputStream: java.lang.Object readObject()>");
        assertNotNull(nativeDeser);
        assertEquals("base", nativeDeser.getIndex());
        assertEquals("CustomDeserialization", nativeDeser.getVulnType());
        assertEquals("custom-category", nativeDeser.getCategory());

        assertNotNull(findSink(migrated,
                "<org.apache.commons.lang3.SerializationUtils: java.lang.Object deserialize(byte[])>"));
        assertNotNull(findSink(migrated,
                "<groovy.lang.GroovyShell: groovy.lang.Script parse(java.lang.String)>"));
        SinkRule reflectionInvoke = findSink(migrated,
                "<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>");
        assertNotNull(reflectionInvoke);
        assertEquals(1, reflectionInvoke.getIndex());
        assertNotNull(findSink(migrated,
                "<example.Sink: void consume(java.lang.String)>"));

        String persisted = Files.readString(rules, StandardCharsets.UTF_8);
        assertTrue(persisted.contains("rules_version: 3"));
    }

    private static SinkRule findSink(Config config, String signature) {
        return config.getSinks().stream()
                .filter(rule -> signature.equals(rule.getSignature()))
                .findFirst()
                .orElse(null);
    }
}
