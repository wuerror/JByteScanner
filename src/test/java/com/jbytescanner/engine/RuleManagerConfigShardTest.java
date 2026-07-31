package com.jbytescanner.engine;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.jbytescanner.config.Config;
import com.jbytescanner.config.ScanConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuleManagerConfigShardTest {

    @TempDir
    Path tempDir;

    @Test
    void shardsLargeGeneratedTaintConfigBelowSnakeYamlLimit() throws Exception {
        Config config = new Config();
        config.setScanConfig(new ScanConfig());
        config.setSources(new ArrayList<>());
        config.setSinks(new ArrayList<>());
        config.setTransfers(new ArrayList<>());

        int entryCount = 35_000;
        List<String> entries = new ArrayList<>(entryCount);
        String padding = "VeryLongBusinessPackageName".repeat(4);
        for (int i = 0; i < entryCount; i++) {
            entries.add("<com.example." + padding + ".Controller" + i
                    + ": void endpoint(java.lang.String)>");
        }

        String generated = new RuleManager(config)
                .generateTaieConfig(entries, tempDir.toFile(), List.of());
        Path configPath = Path.of(generated);

        assertTrue(Files.isDirectory(configPath));
        List<Path> shards;
        try (var files = Files.list(configPath)) {
            shards = files.filter(path -> path.getFileName().toString().endsWith(".yml"))
                    .sorted()
                    .toList();
        }
        assertTrue(shards.size() > 1);

        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        int sourceCount = 0;
        boolean hasOptions = false;
        for (Path shard : shards) {
            assertTrue(Files.size(shard) <= RuleManager.MAX_TAINT_CONFIG_SHARD_BYTES,
                    () -> "oversized shard: " + shard);
            Map<String, Object> document = mapper.readValue(shard.toFile(), new TypeReference<>() {});
            if (document.containsKey("call-site-mode")) {
                hasOptions = true;
            }
            Object sources = document.get("sources");
            if (sources instanceof List<?> list) {
                sourceCount += list.size();
            }
        }

        assertTrue(hasOptions);
        assertEquals(entryCount, sourceCount);
    }
}
