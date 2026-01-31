package com.jbytescanner.analysis;

import com.jbytescanner.config.Config;
import com.jbytescanner.config.SinkRule;
import com.jbytescanner.config.SourceRule;
import soot.SootMethod;
import soot.tagkit.AnnotationTag;
import soot.tagkit.VisibilityAnnotationTag;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RuleManager {
    private final Config config;
    private final Map<String, SinkRule> sinkSignatureMap = new HashMap<>();
    private final Map<String, SourceRule> sourceSignatureMap = new HashMap<>();

    public RuleManager(Config config) {
        this.config = config;
        indexRules();
    }

    private void indexRules() {
        if (config.getSinks() != null) {
            for (SinkRule rule : config.getSinks()) {
                if ("method".equalsIgnoreCase(rule.getType())) {
                    sinkSignatureMap.put(rule.getSignature(), rule);
                }
            }
        }
        if (config.getSources() != null) {
            for (SourceRule rule : config.getSources()) {
                if ("method".equalsIgnoreCase(rule.getType())) {
                    sourceSignatureMap.put(rule.getSignature(), rule);
                }
            }
        }
    }

    public boolean isSink(SootMethod method) {
        // Exact signature match
        // Future improvement: fuzzy match or regex
        return sinkSignatureMap.containsKey(method.getSignature());
    }
    
    public SinkRule getSinkRule(SootMethod method) {
        return sinkSignatureMap.get(method.getSignature());
    }

    public boolean isSource(SootMethod method) {
        return sourceSignatureMap.containsKey(method.getSignature());
    }

    /**
     * Check if a parameter is a source based on annotations (e.g. @RequestParam)
     */
    public boolean isSource(SootMethod method, int paramIndex) {
        // Check method parameter annotations
        // This requires parsing method annotations which Soot stores in VisibilityParameterAnnotationTag
        // For Phase 4 MVP, we will rely on api.txt entry points implicitly being tainted
        // But if rules.yaml defines specific annotation sources, we check here.
        return false; // TODO: Implement annotation checking logic
    }
}
