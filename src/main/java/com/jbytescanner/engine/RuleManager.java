package com.jbytescanner.engine;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.jbytescanner.config.Config;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.config.SourceRule;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class RuleManager {
    private static final Logger logger = LoggerFactory.getLogger(RuleManager.class);

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
        // Pre-scan: find which configured sinks are actually invoked in app bytecode.
        // Skips sinks not referenced → avoids "Cannot find sink method" in Tai-e.
        Set<String> confirmedSinkKeys = null;
        if (appJars != null && !appJars.isEmpty()) {
            confirmedSinkKeys = scanAppJarsForSinks(appJars);
            logger.info("ASM pre-scan confirmed {}/{} sink class.method pairs are referenced in app bytecode.",
                    confirmedSinkKeys.size(), buildSinkKeySet().size());
        }
        Map<String, Object> taieConfig = new HashMap<>();

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
                    source.put("index", "result"); // Default to return value
                    taieSources.add(source);
                }
                // Tai-e doesn't directly support "annotation" sources out of the box in yaml
                // We'd have to pre-process them into method signatures or write a custom TaintConfigProvider.
                // For MVP, we rely on the entry points which are derived from annotations anyway!
            }
        }
        taieConfig.put("sources", taieSources);

        // 2. Convert Sinks
        List<Map<String, Object>> taieSinks = new ArrayList<>();
        for (SinkRule sink : sinks) {
            if (sink.getSignature() != null) {
                // Filter: skip sinks not invoked in app bytecode (avoids "Cannot find" in Tai-e)
                if (confirmedSinkKeys != null) {
                    String sinkKey = extractSinkKey(sink.getSignature());
                    if (sinkKey == null || !confirmedSinkKeys.contains(sinkKey)) {
                        logger.debug("Skipping sink not referenced in app bytecode: {}", sink.getSignature());
                        continue;
                    }
                }
                // Only add index entries for params that actually exist in the sink method.
                // Out-of-range indices cause IndexOutOfBoundsException in Tai-e's taint config parser.
                int paramCount = parseParamCount(sink.getSignature());
                for (int i = 0; i < paramCount; i++) {
                    Map<String, Object> taieSink = new HashMap<>();
                    taieSink.put("method", sink.getSignature());
                    taieSink.put("index", i);
                    taieSinks.add(taieSink);
                }
                // NOTE: We intentionally do NOT add index:"base" here.
                // "base" means the receiver object is tainted, which is almost never
                // the case for our target vuln patterns (XSS, SQLi, RCE, PathTraversal).
                // More importantly, static sinks (Paths.get, Files.write, JSON.parse, etc.)
                // would throw ClassCastException in InvokeUtils.getVar() when "base" is used,
                // because InvokeStatic cannot be cast to InvokeInstanceExp.
            }
        }
        taieConfig.put("sinks", taieSinks);

        // 3. Transfers (Basic String transfers for standard operation)
        List<Map<String, Object>> transfers = new ArrayList<>();
        
        // StringBuilder
        addTransfer(transfers, "<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>", "0", "base");
        addTransfer(transfers, "<java.lang.StringBuilder: java.lang.String toString()>", "base", "result");
        // StringBuffer
        addTransfer(transfers, "<java.lang.StringBuffer: java.lang.StringBuffer append(java.lang.String)>", "0", "base");
        addTransfer(transfers, "<java.lang.StringBuffer: java.lang.String toString()>", "base", "result");
        // String
        addTransfer(transfers, "<java.lang.String: java.lang.String concat(java.lang.String)>", "base", "result");
        addTransfer(transfers, "<java.lang.String: java.lang.String concat(java.lang.String)>", "0", "result");
        
        taieConfig.put("transfers", transfers);

        // Write to file
        File configFile = new File(workspaceDir, "taint-config.yml");
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        try {
            mapper.writeValue(configFile, taieConfig);
            logger.info("Tai-e taint-config.yml generated at: {}", configFile.getAbsolutePath());
            return configFile.getAbsolutePath();
        } catch (IOException e) {
            logger.error("Failed to write Tai-e taint-config.yml", e);
            return null;
        }
    }
    
    private void addTransfer(List<Map<String, Object>> transfers, String method, String from, String to) {
        Map<String, Object> t = new HashMap<>();
        t.put("method", method);
        t.put("from", from);
        t.put("to", to);
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