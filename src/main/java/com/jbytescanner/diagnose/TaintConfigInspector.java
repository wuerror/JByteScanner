package com.jbytescanner.diagnose;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads the actual generated Tai-e taint configuration (single YAML file or
 * sharded directory) and reports which exact rules were emitted.
 */
public final class TaintConfigInspector {

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

    private TaintConfigInspector() {
    }

    public record EmittedSink(String method, String index) {
    }

    public record EmittedSource(String kind, String method, String index, String type) {
    }

    public static final class EmittedConfig {
        private final List<EmittedSink> sinks;
        private final List<EmittedSource> sources;
        private final List<String> errors;
        private final String callSiteMode;

        EmittedConfig(List<EmittedSink> sinks, List<EmittedSource> sources,
                      List<String> errors, String callSiteMode) {
            this.sinks = List.copyOf(sinks);
            this.sources = List.copyOf(sources);
            this.errors = List.copyOf(errors);
            this.callSiteMode = callSiteMode;
        }

        public List<EmittedSink> sinks() {
            return sinks;
        }

        public List<EmittedSource> sources() {
            return sources;
        }

        public List<String> errors() {
            return errors;
        }

        public String callSiteMode() {
            return callSiteMode;
        }

        public List<String> sinkIndexes(String signature) {
            String canonical = TaiEMethodSignature.canonicalize(signature);
            List<String> indexes = new ArrayList<>();
            for (EmittedSink sink : sinks) {
                if (sink.method().equals(canonical)) {
                    indexes.add(sink.index());
                }
            }
            return indexes;
        }

        public boolean hasSink(String signature, String index) {
            String canonical = TaiEMethodSignature.canonicalize(signature);
            String wantedIndex = TaiEMethodSignature.normalizeIndex(index);
            for (EmittedSink sink : sinks) {
                if (!sink.method().equals(canonical)) {
                    continue;
                }
                if (wantedIndex == null || wantedIndex.equals(sink.index())) {
                    return true;
                }
            }
            return false;
        }

        public boolean hasSource(String signature, String index) {
            String canonical = TaiEMethodSignature.canonicalize(signature);
            String wantedIndex = TaiEMethodSignature.normalizeIndex(index);
            for (EmittedSource source : sources) {
                if (!source.method().equals(canonical)) {
                    continue;
                }
                if (wantedIndex == null || wantedIndex.equals(source.index())) {
                    return true;
                }
            }
            return false;
        }

        public List<EmittedSource> sourcesFor(String signature) {
            String canonical = TaiEMethodSignature.canonicalize(signature);
            return sources.stream().filter(source -> source.method().equals(canonical)).toList();
        }
    }

    public static EmittedConfig read(Path configPath) {
        List<EmittedSink> sinks = new ArrayList<>();
        List<EmittedSource> sources = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        String[] callSiteMode = {null};
        if (configPath == null || !Files.exists(configPath)) {
            errors.add("taint config not found: " + configPath);
            return new EmittedConfig(sinks, sources, errors, null);
        }
        List<Path> documents = new ArrayList<>();
        if (Files.isDirectory(configPath)) {
            try (var stream = Files.walk(configPath)) {
                stream.filter(Files::isRegularFile)
                        .filter(path -> path.getFileName().toString().endsWith(".yml")
                                || path.getFileName().toString().endsWith(".yaml"))
                        .sorted(Comparator.comparing(Path::toString))
                        .forEach(documents::add);
            } catch (IOException e) {
                errors.add("failed to list taint config shards: " + e.getMessage());
            }
        } else {
            documents.add(configPath);
        }
        for (Path document : documents) {
            try {
                Map<?, ?> root = YAML.readValue(document.toFile(), Map.class);
                readDocument(root, sinks, sources, callSiteMode, document, errors);
            } catch (Exception e) {
                errors.add(document + ": " + e.getMessage());
            }
        }
        return new EmittedConfig(sinks, sources, errors, callSiteMode[0]);
    }

    private static void readDocument(Map<?, ?> root, List<EmittedSink> sinks,
                                      List<EmittedSource> sources, String[] callSiteMode,
                                      Path document, List<String> errors) {
        if (root == null) {
            return;
        }
        if (callSiteMode[0] == null && root.get("call-site-mode") != null) {
            callSiteMode[0] = String.valueOf(root.get("call-site-mode"));
        }
        for (Map<?, ?> sink : maps(root.get("sinks"))) {
            String method = canonicalMethod(sink.get("method"), document, errors);
            if (method == null) {
                continue;
            }
            sinks.add(new EmittedSink(method, normalize(sink.get("index"))));
        }
        for (Map<?, ?> source : maps(root.get("sources"))) {
            String method = canonicalMethod(source.get("method"), document, errors);
            if (method == null) {
                continue;
            }
            String kind = source.get("kind") == null ? null : String.valueOf(source.get("kind"));
            String type = source.get("type") == null ? null : String.valueOf(source.get("type"));
            sources.add(new EmittedSource(kind, method, normalize(source.get("index")), type));
        }
    }

    private static String canonicalMethod(Object value, Path document, List<String> errors) {
        if (value == null) {
            errors.add(document + ": rule without method");
            return null;
        }
        String raw = String.valueOf(value).trim();
        TaiEMethodSignature parsed = TaiEMethodSignature.parseNullable(raw);
        if (parsed == null) {
            errors.add(document + ": malformed method signature: " + raw);
            return raw;
        }
        return parsed.canonical();
    }

    private static String normalize(Object index) {
        return TaiEMethodSignature.normalizeIndex(index);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<?, ?>> maps(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        List<Map<?, ?>> result = new ArrayList<>();
        for (Object item : list) {
            if (item instanceof Map<?, ?> map) {
                result.add(map);
            }
        }
        return result;
    }

    public static Map<String, Object> summarize(EmittedConfig config) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("sinkCount", config == null ? 0 : config.sinks().size());
        summary.put("sourceCount", config == null ? 0 : config.sources().size());
        summary.put("callSiteMode", config == null ? null : config.callSiteMode());
        summary.put("errors", config == null ? List.of() : config.errors());
        return summary;
    }
}
