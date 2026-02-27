package com.jbytescanner.engine;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.jbytescanner.config.Config;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.config.SourceRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
     * @param entryMethodSignatures The signatures of the entry points discovered in Phase 2
     * @param workspaceDir          The workspace directory where taint-config.yml will be written
     * @return The absolute path to the generated taint-config.yml
     */
    public String generateTaieConfig(List<String> entryMethodSignatures, File workspaceDir) {
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
                // Only add index entries for params that actually exist in the sink method.
                // Out-of-range indices cause IndexOutOfBoundsException in Tai-e's taint config parser.
                int paramCount = parseParamCount(sink.getSignature());
                for (int i = 0; i < paramCount; i++) {
                    Map<String, Object> taieSink = new HashMap<>();
                    taieSink.put("method", sink.getSignature());
                    taieSink.put("index", i);
                    taieSinks.add(taieSink);
                }
                // Also base object for some sinks (like Statement.executeQuery)
                Map<String, Object> baseSink = new HashMap<>();
                baseSink.put("method", sink.getSignature());
                baseSink.put("index", "base");
                taieSinks.add(baseSink);
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
}