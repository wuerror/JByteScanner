package com.jbytescanner.engine;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.jbytescanner.config.Config;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.config.SourceRule;
import com.jbytescanner.config.TransferRule;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class RuleManager {
    private static final Logger logger = LoggerFactory.getLogger(RuleManager.class);
    // SnakeYAML defaults to 3,145,728 code points per document. Keep generated
    // documents comfortably below that limit (UTF-8 byte size is conservative).
    static final int MAX_TAINT_CONFIG_SHARD_BYTES = 2_500_000;
    private static final int TAINT_CONFIG_SECTION_BATCH_SIZE = 3_000;
    private static final String TAINT_CONFIG_FILE = "taint-config.yml";
    private static final String TAINT_CONFIG_DIRECTORY = "taint-config.d";

    private final Config jbsConfig;
    private final List<SinkRule> sinks;

    public RuleManager(Config config) {
        this.jbsConfig = config;
        this.sinks = config.getSinks() != null ? config.getSinks() : new ArrayList<>();
    }

    /**
     * Translates JByteScanner's Config into Tai-e's taint-config.yml format.
     * Also registers entry point sources.
     *
     * <p>This method uses an ASM pre-scan of app bytecode to determine which configured
     * sinks are actually invoked. Only confirmed sinks are written to the taint-config.
     * This mirrors the main branch's ASM approach: sink detection works purely on bytecode
     * call-site instructions, requiring no library JARs on the classpath.
     *
     * <p>When a sink IS referenced in app bytecode, Tai-e's {@code -ap} (allow-phantom)
     * mode creates a phantom class/method for it during World build, so
     * {@code YamlTaintConfigProvider} can find it without the actual library JAR.
     *
     * @param entryMethodSignatures The signatures of the entry points discovered in Phase 2
     * @param workspaceDir          The workspace directory where taint-config.yml will be written
     * @param appJars               App JAR paths to pre-scan (targetAppJars + depAppJars);
     *                              pass null or empty to skip pre-scan and include all sinks
     * @return The absolute path to the generated taint-config.yml
     */
    public String generateTaieConfig(List<String> entryMethodSignatures, File workspaceDir,
                                      List<String> appJars) {
        JBSScanEntryPointPlugin.supplementalEntrySignatures = List.of();
        // Pre-scan: find which configured sinks are actually invoked in app bytecode.
        // Skips sinks not referenced → avoids "Cannot find sink method" in Tai-e.
        Set<String> confirmedSinkKeys = null;
        if (appJars != null && !appJars.isEmpty()) {
            confirmedSinkKeys = scanAppJarsForSinks(appJars);
            logger.info("ASM pre-scan confirmed {}/{} sink class.method pairs are referenced in app bytecode.",
                    confirmedSinkKeys.size(), buildSinkKeySet().size());
        }
        Map<String, Object> taieConfig = new HashMap<>();
        // Tai-e normally applies call sources/sinks/transfers only after PTA resolves a
        // callee. Interface-typed framework values often have no concrete points-to
        // object at synthetic Web entry points, so the call edge is absent even though
        // the invoke statement is reachable. Call-site mode matches the declared method
        // reference in reachable IR and keeps these flows analyzable.
        boolean callSiteMode = jbsConfig.getScanConfig() == null
                || jbsConfig.getScanConfig().isTaintCallSiteMode();
        taieConfig.put("call-site-mode", callSiteMode);

        // 1. Convert Sources
        List<Map<String, Object>> taieSources = new ArrayList<>();
        
        // Add entry points as parameter sources.
        // CRITICAL: only add indices that actually exist in the method's parameter list.
        // Tai-e's taint config parser calls method.getParamType(index) which throws
        // IndexOutOfBoundsException for out-of-range indices, aborting config loading.
        for (String entrySig : entryMethodSignatures) {
            int paramCount = parseParamCount(entrySig);
            for (int i = 0; i < paramCount; i++) {
                Map<String, Object> source = new HashMap<>();
                source.put("kind", "param");
                source.put("method", entrySig);
                source.put("index", i);
                taieSources.add(source);
            }
        }

        // Add explicit sources from rules.yaml
        if (jbsConfig.getSources() != null) {
            for (SourceRule src : jbsConfig.getSources()) {
                if ("method".equals(src.getType()) && src.getSignature() != null) {
                    Map<String, Object> source = new HashMap<>();
                    source.put("kind", "call");
                    source.put("method", src.getSignature());
                    source.put("index", src.getIndex() != null
                            ? normalizeIndex(src.getIndex())
                            : "result");
                    if (src.getTaintType() != null && !src.getTaintType().isBlank()) {
                        // Useful for generic persistence APIs such as Object get(key, Class):
                        // the concrete taint type can then survive casts to the requested model.
                        source.put("type", src.getTaintType());
                    }
                    taieSources.add(source);
                }
                // Tai-e doesn't directly support "annotation" sources out of the box in yaml
                // We'd have to pre-process them into method signatures or write a custom TaintConfigProvider.
                // For MVP, we rely on the entry points which are derived from annotations anyway!
            }
        }
        boolean persistentSourceAnalysis = jbsConfig.getScanConfig() == null
                || jbsConfig.getScanConfig().isPersistentSourceAnalysis();
        if (persistentSourceAnalysis && appJars != null && !appJars.isEmpty()) {
            Set<TypedCallSource> persistentSources = scanAppJarsForTypedCacheSources(appJars);
            Map<String, Set<String>> typesByGetter = new HashMap<>();
            for (TypedCallSource persistentSource : persistentSources) {
                typesByGetter.computeIfAbsent(persistentSource.method(), ignored -> new HashSet<>())
                        .add(persistentSource.type());
            }

            // Tai-e 0.5.4 cannot reliably distinguish multiple differently typed call
            // sources declared for the same method. In call-site mode those declarations
            // all match every invocation, and SourcePoint ordering may retain an unrelated
            // model type for a given call site. Emit the cache getter directly only when
            // it has one inferred model type. For polymorphic typed getters, model the
            // persisted model's accessor results instead (for example
            // GroovyScript.getContent(): String), which is both call-site stable and
            // semantically represents data read from persistent storage.
            Set<String> polymorphicGetterTypes = new HashSet<>();
            Set<String> emittedSources = new HashSet<>();
            int directSourceCount = 0;
            for (TypedCallSource persistentSource : persistentSources) {
                Set<String> getterTypes = typesByGetter.get(persistentSource.method());
                if (getterTypes != null && getterTypes.size() > 1) {
                    polymorphicGetterTypes.add(persistentSource.type());
                    continue;
                }
                if (addCallSource(taieSources, emittedSources,
                        persistentSource.method(), persistentSource.type())) {
                    directSourceCount++;
                }
            }

            Set<ModelAccessorSource> accessorSources = polymorphicGetterTypes.isEmpty()
                    ? Set.of()
                    : scanAppJarsForModelAccessors(appJars, polymorphicGetterTypes);
            int accessorSourceCount = 0;
            for (ModelAccessorSource accessorSource : accessorSources) {
                if (addCallSource(taieSources, emittedSources,
                        accessorSource.method(), accessorSource.type())) {
                    accessorSourceCount++;
                }
            }

            JBSScanEntryPointPlugin.supplementalEntrySignatures = persistentSources.stream()
                    .map(TypedCallSource::containerMethod)
                    .distinct()
                    .toList();
            long polymorphicGetterCount = typesByGetter.values().stream()
                    .filter(types -> types.size() > 1)
                    .count();
            logger.info("ASM pre-scan inferred {} typed persistent-data read pattern(s) "
                            + "in {} containing method(s); emitted {} direct getter source(s) "
                            + "and {} model accessor source(s) for {} polymorphic getter(s).",
                    persistentSources.size(),
                    JBSScanEntryPointPlugin.supplementalEntrySignatures.size(),
                    directSourceCount, accessorSourceCount, polymorphicGetterCount);
        }
        taieConfig.put("sources", taieSources);

        // 2. Convert Sinks
        List<Map<String, Object>> taieSinks = new ArrayList<>();
        for (SinkRule sink : sinks) {
            if (sink.getSignature() == null) {
                continue;
            }

            // Filter: skip sinks not invoked in app bytecode (avoids "Cannot find" in Tai-e).
            if (confirmedSinkKeys != null) {
                String sinkKey = extractSinkKey(sink.getSignature());
                if (sinkKey == null || !confirmedSinkKeys.contains(sinkKey)) {
                    logger.debug("Skipping sink not referenced in app bytecode: {}", sink.getSignature());
                    continue;
                }
            }

            // Prefer an explicitly configured sensitive index. This is required for
            // receiver-based, zero-argument sinks such as ObjectInputStream.readObject().
            if (sink.getIndex() != null) {
                addSink(taieSinks, sink.getSignature(), normalizeIndex(sink.getIndex()));
                continue;
            }

            // Legacy compatibility: if no index is configured, mark every parameter.
            int paramCount = parseParamCount(sink.getSignature());
            for (int i = 0; i < paramCount; i++) {
                addSink(taieSinks, sink.getSignature(), i);
            }
            if (paramCount == 0) {
                logger.warn("Zero-argument sink has no configured index and is inactive: {}. " +
                        "Use index: base for an instance receiver sink.", sink.getSignature());
            }
        }
        taieConfig.put("sinks", taieSinks);

        // 3. Transfers
        List<Map<String, Object>> transfers = new ArrayList<>();

        // Core String propagation.
        addTransfer(transfers, "<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>", "0", "base", null);
        addTransfer(transfers, "<java.lang.StringBuilder: java.lang.String toString()>", "base", "result", null);
        addTransfer(transfers, "<java.lang.StringBuffer: java.lang.StringBuffer append(java.lang.String)>", "0", "base", null);
        addTransfer(transfers, "<java.lang.StringBuffer: java.lang.String toString()>", "base", "result", null);
        addTransfer(transfers, "<java.lang.String: java.lang.String concat(java.lang.String)>", "base", "result", null);
        addTransfer(transfers, "<java.lang.String: java.lang.String concat(java.lang.String)>", "0", "result", null);
        addTransfer(transfers, "<java.lang.String: java.lang.String replaceAll(java.lang.String,java.lang.String)>", "base", "result", null);

        // Common upload/archive wrappers used before deserialization. With only-app:true,
        // Tai-e does not analyze these library bodies, so their value-flow summaries must
        // be explicit or the MultipartFile -> InputStream -> byte[] chain is broken.
        addTransfer(transfers, "<org.springframework.web.multipart.MultipartFile: java.io.InputStream getInputStream()>", "base", "result", null);
        addTransfer(transfers, "<org.apache.commons.compress.archivers.zip.ZipArchiveInputStream: void <init>(java.io.InputStream)>", "0", "base", null);
        addTransfer(transfers, "<org.apache.commons.compress.archivers.zip.ZipArchiveInputStream: void <init>(java.io.InputStream,java.lang.String)>", "0", "base", null);
        addTransfer(transfers, "<org.apache.commons.io.IOUtils: byte[] toByteArray(java.io.InputStream)>", "0", "result", null);

        // Collection/JSON transformations commonly used by reflection-based debug APIs.
        // These library bodies are not analyzed with only-app:true, so preserve taint as
        // request strings are parsed, collected, converted, and passed to Method.invoke.
        addTransfer(transfers, "<com.alibaba.fastjson.JSON: com.alibaba.fastjson.JSONArray parseArray(java.lang.String)>", "0", "result", null);
        addTransfer(transfers, "<com.alibaba.fastjson.JSON: java.lang.Object parseObject(java.lang.String,java.lang.reflect.Type,com.alibaba.fastjson.parser.Feature[])>", "0", "result", null);
        addTransfer(transfers, "<com.alibaba.fastjson.JSONArray: java.util.stream.Stream stream()>", "base", "result", null);
        addTransfer(transfers, "<java.util.stream.Stream: java.util.stream.Stream map(java.util.function.Function)>", "base", "result", null);
        addTransfer(transfers, "<java.util.stream.Stream: java.lang.Object collect(java.util.stream.Collector)>", "base", "result", null);
        addTransfer(transfers, "<java.util.List: java.lang.Object get(int)>", "base", "result", null);
        addTransfer(transfers, "<java.util.List: boolean add(java.lang.Object)>", "0", "base", null);
        addTransfer(transfers, "<java.util.List: java.lang.Object[] toArray()>", "base", "result", null);

        // Project-specific summaries can be supplied in rules.yaml without changing Java.
        if (jbsConfig.getTransfers() != null) {
            for (TransferRule transfer : jbsConfig.getTransfers()) {
                if (transfer.getMethod() == null || transfer.getFrom() == null || transfer.getTo() == null) {
                    logger.warn("Skipping incomplete transfer rule: {}", transfer);
                    continue;
                }
                addTransfer(transfers, transfer.getMethod(), transfer.getFrom(), transfer.getTo(), transfer.getType());
            }
        }

        taieConfig.put("transfers", transfers);

        return writeTaieConfig(workspaceDir, taieConfig);
    }

    /**
     * Writes a small Tai-e configuration as one YAML document. Large applications can
     * generate tens of thousands of entry-point sources, which exceed SnakeYAML's
     * per-document code-point limit. Tai-e 0.5.4 accepts a directory of YAML files and
     * merges them, so large configurations are emitted as bounded shards instead.
     */
    private String writeTaieConfig(File workspaceDir, Map<String, Object> taieConfig) {
        File configFile = new File(workspaceDir, TAINT_CONFIG_FILE);
        Path configDirectory = new File(workspaceDir, TAINT_CONFIG_DIRECTORY).toPath();
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        try {
            byte[] completeDocument = mapper.writeValueAsBytes(taieConfig);
            if (completeDocument.length <= MAX_TAINT_CONFIG_SHARD_BYTES) {
                deleteRecursively(configDirectory);
                Files.write(configFile.toPath(), completeDocument);
                logger.info("Tai-e taint config generated at: {} ({} bytes)",
                        configFile.getAbsolutePath(), completeDocument.length);
                return configFile.getAbsolutePath();
            }

            Files.deleteIfExists(configFile.toPath());
            deleteRecursively(configDirectory);
            Files.createDirectories(configDirectory);

            int sequence = 0;
            Map<String, Object> options = new LinkedHashMap<>();
            options.put("call-site-mode", taieConfig.get("call-site-mode"));
            sequence = writeShard(mapper, configDirectory, sequence, "options", options);
            sequence = writeSectionShards(mapper, configDirectory, sequence,
                    "sources", asList(taieConfig.get("sources")));
            sequence = writeSectionShards(mapper, configDirectory, sequence,
                    "sinks", asList(taieConfig.get("sinks")));
            sequence = writeSectionShards(mapper, configDirectory, sequence,
                    "transfers", asList(taieConfig.get("transfers")));

            logger.info("Tai-e taint config exceeded {} bytes ({} bytes); generated {} YAML shard(s) at: {}",
                    MAX_TAINT_CONFIG_SHARD_BYTES, completeDocument.length, sequence,
                    configDirectory.toAbsolutePath());
            return configDirectory.toAbsolutePath().toString();
        } catch (IOException e) {
            logger.error("Failed to write Tai-e taint config", e);
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private List<Object> asList(Object value) {
        return value instanceof List<?> list ? (List<Object>) list : List.of();
    }

    private int writeSectionShards(ObjectMapper mapper, Path directory, int sequence,
                                   String key, List<?> values) throws IOException {
        for (int start = 0; start < values.size(); start += TAINT_CONFIG_SECTION_BATCH_SIZE) {
            int end = Math.min(values.size(), start + TAINT_CONFIG_SECTION_BATCH_SIZE);
            sequence = writeSectionChunk(mapper, directory, sequence, key,
                    new ArrayList<>(values.subList(start, end)));
        }
        return sequence;
    }

    private int writeSectionChunk(ObjectMapper mapper, Path directory, int sequence,
                                  String key, List<?> values) throws IOException {
        Map<String, Object> section = new LinkedHashMap<>();
        section.put(key, values);
        byte[] yaml = mapper.writeValueAsBytes(section);
        if (yaml.length > MAX_TAINT_CONFIG_SHARD_BYTES && values.size() > 1) {
            int middle = values.size() / 2;
            sequence = writeSectionChunk(mapper, directory, sequence, key,
                    new ArrayList<>(values.subList(0, middle)));
            return writeSectionChunk(mapper, directory, sequence, key,
                    new ArrayList<>(values.subList(middle, values.size())));
        }
        if (yaml.length > MAX_TAINT_CONFIG_SHARD_BYTES) {
            throw new IOException("Single " + key + " entry exceeds Tai-e YAML shard limit");
        }
        return writeShard(mapper, directory, sequence, key, section);
    }

    private int writeShard(ObjectMapper mapper, Path directory, int sequence,
                           String label, Map<String, Object> content) throws IOException {
        byte[] yaml = mapper.writeValueAsBytes(content);
        if (yaml.length > MAX_TAINT_CONFIG_SHARD_BYTES) {
            throw new IOException("Tai-e YAML shard exceeds safe limit: " + label);
        }
        Path output = directory.resolve(String.format("%03d-%s.yml", sequence, label));
        Files.write(output, yaml);
        return sequence + 1;
    }

    private void deleteRecursively(Path path) throws IOException {
        if (!Files.exists(path)) {
            return;
        }
        try (var walk = Files.walk(path)) {
            for (Path item : walk.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(item);
            }
        }
    }
    
    private void addSink(List<Map<String, Object>> sinks, String method, Object index) {
        Map<String, Object> sink = new HashMap<>();
        sink.put("method", method);
        sink.put("index", index);
        sinks.add(sink);
    }

    private Object normalizeIndex(Object index) {
        if (index instanceof Number number) {
            return number.intValue();
        }
        String value = String.valueOf(index).trim();
        if (value.matches("\\d+")) {
            return Integer.parseInt(value);
        }
        return value;
    }

    private void addTransfer(List<Map<String, Object>> transfers, String method,
                             String from, String to, String type) {
        Map<String, Object> t = new HashMap<>();
        t.put("method", method);
        t.put("from", from);
        t.put("to", to);
        if (type != null && !type.isBlank()) {
            t.put("type", type);
        }
        transfers.add(t);
    }

    public List<SinkRule> getSinks() {
        return sinks;
    }
    
    public SinkRule getRuleForSink(String methodSignature) {
        for (SinkRule rule : sinks) {
            if (methodSignature.equals(rule.getSignature())) {
                return rule;
            }
        }
        return null;
    }

    /**
     * Parses the number of parameters from a Tai-e method signature string.
     * Format: {@code <com.example.Class: ReturnType methodName(paramType1,paramType2)>}
     * <p>
     * Returns 0 for incomplete signatures (e.g., {@code <Class: service>}) that
     * lack parentheses — these are usually servlet "service" entries that should
     * not have param sources generated.
     */
    static int parseParamCount(String methodSig) {
        int openParen = methodSig.lastIndexOf('(');
        int closeParen = methodSig.lastIndexOf(')');
        if (openParen < 0 || closeParen <= openParen) return 0;
        String paramStr = methodSig.substring(openParen + 1, closeParen).trim();
        if (paramStr.isEmpty()) return 0;
        // JVM param types use fully qualified names; commas only appear as param separators
        return paramStr.split(",").length;
    }

    /**
     * Extracts an "internalClassName.methodName" lookup key from a Tai-e method signature.
     * The class name uses slash-separated internal form to match what ASM reports in
     * {@code visitMethodInsn(opcode, owner, name, ...)}.
     *
     * <p>Examples:
     * <ul>
     *   <li>{@code <java.lang.Runtime: java.lang.Process exec(java.lang.String)>}
     *       → {@code java/lang/Runtime.exec}</li>
     *   <li>{@code <java.net.URL: void <init>(java.lang.String)>}
     *       → {@code java/net/URL.<init>}</li>
     * </ul>
     */
    private String extractSinkKey(String signature) {
        if (signature == null) return null;
        // Format: <com.example.Class: ReturnType methodName(...)>
        int colon = signature.indexOf(':');
        int openParen = signature.lastIndexOf('(');
        if (colon < 0 || openParen < 0) return null;
        String className = signature.substring(1, colon).trim().replace('.', '/');
        // afterColon: "ReturnType methodName" or "void <init>"
        String afterColon = signature.substring(colon + 1, openParen).trim();
        int lastSpace = afterColon.lastIndexOf(' ');
        if (lastSpace < 0) return null;
        String methodName = afterColon.substring(lastSpace + 1).trim();
        return className + "." + methodName;
    }

    /**
     * Builds the complete set of configured sink keys for quick lookup during ASM scanning.
     */
    private Set<String> buildSinkKeySet() {
        Set<String> keys = new HashSet<>();
        for (SinkRule sink : sinks) {
            String key = extractSinkKey(sink.getSignature());
            if (key != null) keys.add(key);
        }
        return keys;
    }

    /**
     * Scans app JARs/directories with ASM to discover which configured sink class.method
     * pairs are actually referenced as INVOKE* call sites in app bytecode.
     *
     * <p>This mirrors the main branch's ASM approach: works purely on bytecode call-site
     * instructions, requiring no library JARs on the classpath. Only confirmed sinks are
     * written to the taint-config, preventing "Cannot find sink method" errors in Tai-e.
     *
     * @return Set of "internalClassName.methodName" keys found in bytecode (e.g. "java/lang/Runtime.exec")
     */
    private Set<String> scanAppJarsForSinks(List<String> appJars) {
        Set<String> sinkKeys = buildSinkKeySet();
        Set<String> confirmed = new HashSet<>();
        for (String jarPath : appJars) {
            File f = new File(jarPath);
            if (f.isDirectory()) {
                scanDirectoryForSinks(f, sinkKeys, confirmed);
            } else if (jarPath.endsWith(".jar") || jarPath.endsWith(".war")) {
                scanJarForSinks(jarPath, sinkKeys, confirmed);
            }
        }
        return confirmed;
    }

    private void scanJarForSinks(String jarPath, Set<String> sinkKeys, Set<String> confirmed) {
        try (JarFile jar = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".class")) {
                    try (InputStream in = jar.getInputStream(entry)) {
                        scanClassForSinks(in, sinkKeys, confirmed);
                    } catch (Exception e) {
                        // ignore individual malformed class files
                    }
                }
            }
        } catch (IOException e) {
            logger.warn("ASM pre-scan: failed to open JAR: {}", jarPath);
        }
    }

    private void scanDirectoryForSinks(File dir, Set<String> sinkKeys, Set<String> confirmed) {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isDirectory()) {
                scanDirectoryForSinks(f, sinkKeys, confirmed);
            } else if (f.getName().endsWith(".class")) {
                try (InputStream in = new java.io.FileInputStream(f)) {
                    scanClassForSinks(in, sinkKeys, confirmed);
                } catch (Exception e) {
                    // ignore
                }
            }
        }
    }

    private boolean addCallSource(List<Map<String, Object>> taieSources,
                                  Set<String> emittedSources,
                                  String method, String type) {
        String sourceKey = method + "\0" + type;
        if (!emittedSources.add(sourceKey)) {
            return false;
        }
        Map<String, Object> source = new HashMap<>();
        source.put("kind", "call");
        source.put("method", method);
        source.put("index", "result");
        source.put("type", type);
        taieSources.add(source);
        return true;
    }

    /** A call source whose runtime model type is conveyed by a Class literal argument. */
    private record TypedCallSource(String method, String type, String containerMethod) {
    }

    /** A reference-valued accessor declared by a model loaded from persistent storage. */
    private record ModelAccessorSource(String method, String type) {
    }

    /**
     * Finds typed cache reads of the common form {@code Object get(String, Class<T>)}.
     * The returned Object is modeled with the adjacent class literal's concrete type,
     * allowing stored taint to survive the bytecode CHECKCAST to the requested model.
     */
    private Set<TypedCallSource> scanAppJarsForTypedCacheSources(List<String> appJars) {
        Set<TypedCallSource> sources = new HashSet<>();
        for (String jarPath : appJars) {
            File file = new File(jarPath);
            if (file.isDirectory()) {
                scanDirectoryForTypedCacheSources(file, sources);
            } else if (jarPath.endsWith(".jar") || jarPath.endsWith(".war")) {
                scanJarForTypedCacheSources(jarPath, sources);
            }
        }
        return sources;
    }

    private Set<ModelAccessorSource> scanAppJarsForModelAccessors(
            List<String> appJars, Set<String> modelTypes) {
        Set<ModelAccessorSource> sources = new HashSet<>();
        Set<String> internalModelNames = modelTypes.stream()
                .map(type -> type.replace('.', '/'))
                .collect(java.util.stream.Collectors.toSet());
        for (String jarPath : appJars) {
            File file = new File(jarPath);
            if (file.isDirectory()) {
                scanDirectoryForModelAccessors(file, internalModelNames, sources);
            } else if (jarPath.endsWith(".jar") || jarPath.endsWith(".war")) {
                scanJarForModelAccessors(jarPath, internalModelNames, sources);
            }
        }
        return sources;
    }

    private void scanJarForModelAccessors(String jarPath, Set<String> modelTypes,
                                          Set<ModelAccessorSource> sources) {
        try (JarFile jar = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (!entry.getName().endsWith(".class")
                        || !modelTypes.contains(entry.getName()
                        .substring(0, entry.getName().length() - ".class".length()))) {
                    continue;
                }
                try (InputStream in = jar.getInputStream(entry)) {
                    scanClassForModelAccessors(in, modelTypes, sources);
                } catch (Exception e) {
                    logger.debug("Persistent model-accessor scan skipped malformed class {} in {}",
                            entry.getName(), jarPath, e);
                }
            }
        } catch (IOException e) {
            logger.warn("Persistent model-accessor scan: failed to open JAR: {}", jarPath);
        }
    }

    private void scanDirectoryForModelAccessors(File dir, Set<String> modelTypes,
                                                Set<ModelAccessorSource> sources) {
        File[] files = dir.listFiles();
        if (files == null) {
            return;
        }
        for (File file : files) {
            if (file.isDirectory()) {
                scanDirectoryForModelAccessors(file, modelTypes, sources);
            } else if (file.getName().endsWith(".class")) {
                try (InputStream in = new java.io.FileInputStream(file)) {
                    scanClassForModelAccessors(in, modelTypes, sources);
                } catch (Exception e) {
                    logger.debug("Persistent model-accessor scan skipped malformed class {}", file, e);
                }
            }
        }
    }

    private void scanClassForModelAccessors(InputStream classBytes, Set<String> modelTypes,
                                            Set<ModelAccessorSource> sources) throws IOException {
        ClassNode classNode = new ClassNode(Opcodes.ASM9);
        new ClassReader(classBytes).accept(classNode,
                ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        if (!modelTypes.contains(classNode.name)) {
            return;
        }
        for (MethodNode method : classNode.methods) {
            if ((method.access & (Opcodes.ACC_STATIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0
                    || Type.getArgumentTypes(method.desc).length != 0
                    || !(method.name.startsWith("get") || method.name.startsWith("is"))
                    || "getClass".equals(method.name)) {
                continue;
            }
            Type returnType = Type.getReturnType(method.desc);
            if (returnType.getSort() != Type.OBJECT && returnType.getSort() != Type.ARRAY) {
                continue;
            }
            sources.add(new ModelAccessorSource(
                    toMethodSignature(classNode.name, method.name, method.desc),
                    returnType.getClassName()));
        }
    }

    private void scanJarForTypedCacheSources(String jarPath, Set<TypedCallSource> sources) {
        try (JarFile jar = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (!entry.getName().endsWith(".class")) {
                    continue;
                }
                try (InputStream in = jar.getInputStream(entry)) {
                    scanClassForTypedCacheSources(in, sources);
                } catch (Exception e) {
                    logger.debug("Typed cache-source scan skipped malformed class {} in {}",
                            entry.getName(), jarPath, e);
                }
            }
        } catch (IOException e) {
            logger.warn("Typed cache-source scan: failed to open JAR: {}", jarPath);
        }
    }

    private void scanDirectoryForTypedCacheSources(File dir, Set<TypedCallSource> sources) {
        File[] files = dir.listFiles();
        if (files == null) {
            return;
        }
        for (File file : files) {
            if (file.isDirectory()) {
                scanDirectoryForTypedCacheSources(file, sources);
            } else if (file.getName().endsWith(".class")) {
                try (InputStream in = new java.io.FileInputStream(file)) {
                    scanClassForTypedCacheSources(in, sources);
                } catch (Exception e) {
                    logger.debug("Typed cache-source scan skipped malformed class {}", file, e);
                }
            }
        }
    }

    private void scanClassForTypedCacheSources(InputStream classBytes,
                                                Set<TypedCallSource> sources) throws IOException {
        ClassNode classNode = new ClassNode(Opcodes.ASM9);
        new ClassReader(classBytes).accept(classNode,
                ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        for (MethodNode method : classNode.methods) {
            for (AbstractInsnNode insn : method.instructions) {
                if (!(insn instanceof MethodInsnNode invoke) || !isTypedCacheGetter(invoke)) {
                    continue;
                }
                AbstractInsnNode previous = previousRealInstruction(insn);
                if (!(previous instanceof LdcInsnNode ldc) || !(ldc.cst instanceof Type modelType)) {
                    continue;
                }
                if (modelType.getSort() != Type.OBJECT && modelType.getSort() != Type.ARRAY) {
                    continue;
                }
                String owner = invoke.owner.replace('/', '.');
                Type[] args = Type.getArgumentTypes(invoke.desc);
                String params = java.util.Arrays.stream(args)
                        .map(Type::getClassName)
                        .reduce((left, right) -> left + "," + right)
                        .orElse("");
                String signature = "<" + owner + ": "
                        + Type.getReturnType(invoke.desc).getClassName() + " "
                        + invoke.name + "(" + params + ")>";
                String containerSignature = toMethodSignature(
                        classNode.name, method.name, method.desc);
                sources.add(new TypedCallSource(signature, modelType.getClassName(),
                        containerSignature));
            }
        }
    }

    private String toMethodSignature(String owner, String methodName, String descriptor) {
        Type[] args = Type.getArgumentTypes(descriptor);
        String params = java.util.Arrays.stream(args)
                .map(Type::getClassName)
                .reduce((left, right) -> left + "," + right)
                .orElse("");
        return "<" + owner.replace('/', '.') + ": "
                + Type.getReturnType(descriptor).getClassName() + " "
                + methodName + "(" + params + ")>";
    }

    private boolean isTypedCacheGetter(MethodInsnNode invoke) {
        String ownerSimpleName = invoke.owner.substring(invoke.owner.lastIndexOf('/') + 1)
                .toLowerCase(java.util.Locale.ROOT);
        if (!"get".equals(invoke.name) || !ownerSimpleName.contains("cache")) {
            return false;
        }
        Type[] args = Type.getArgumentTypes(invoke.desc);
        return args.length == 2
                && "java.lang.String".equals(args[0].getClassName())
                && "java.lang.Class".equals(args[1].getClassName())
                && "java.lang.Object".equals(Type.getReturnType(invoke.desc).getClassName());
    }

    private AbstractInsnNode previousRealInstruction(AbstractInsnNode insn) {
        AbstractInsnNode previous = insn.getPrevious();
        while (previous != null && previous.getOpcode() < 0) {
            previous = previous.getPrevious();
        }
        return previous;
    }

    private void scanClassForSinks(InputStream classBytes, Set<String> sinkKeys,
                                    Set<String> confirmed) throws IOException {
        ClassReader reader = new ClassReader(classBytes);
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String mName, String desc,
                                             String sig, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String iName,
                                                String iDesc, boolean isInterface) {
                        // owner is already in internal form (e.g. "java/lang/Runtime")
                        String key = owner + "." + iName;
                        if (sinkKeys.contains(key)) {
                            confirmed.add(key);
                        }
                    }
                };
            }
        }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    }
}