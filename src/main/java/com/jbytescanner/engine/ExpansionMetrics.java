package com.jbytescanner.engine;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ExpansionMetrics {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @JsonProperty("springAnalysis")
    public boolean springAnalysis;

    @JsonProperty("taintCallSiteMode")
    public boolean taintCallSiteMode;

    @JsonProperty("springServiceEntryFallback")
    public boolean springServiceEntryFallback;

    @JsonProperty("persistentSourceMode")
    public String persistentSourceMode;

    @JsonProperty("persistentSourceEnabled")
    public boolean persistentSourceEnabled;

    @JsonProperty("persistentSourceDisableReason")
    public String persistentSourceDisableReason;

    @JsonProperty("persistentSourceMaxPatterns")
    public int persistentSourceMaxPatterns;

    @JsonProperty("persistentSourceMaxSupplementalEntries")
    public int persistentSourceMaxSupplementalEntries;

    @JsonProperty("apiParamSourcesRaw")
    public int apiParamSourcesRaw;

    @JsonProperty("apiParamSourcesUnique")
    public int apiParamSourcesUnique;

    @JsonProperty("explicitRuleSourcesUnique")
    public int explicitRuleSourcesUnique;

    @JsonProperty("persistentPatternsRaw")
    public int persistentPatternsRaw;

    @JsonProperty("persistentPatternsEmitted")
    public int persistentPatternsEmitted;

    @JsonProperty("persistentPatternsTruncated")
    public int persistentPatternsTruncated;

    @JsonProperty("persistentDirectSources")
    public int persistentDirectSources;

    @JsonProperty("persistentAccessorSources")
    public int persistentAccessorSources;

    @JsonProperty("supplementalEntriesRaw")
    public int supplementalEntriesRaw;

    @JsonProperty("supplementalEntriesEmitted")
    public int supplementalEntriesEmitted;

    @JsonProperty("supplementalEntriesTruncated")
    public int supplementalEntriesTruncated;

    @JsonProperty("entryCandidates")
    public int entryCandidates;

    @JsonProperty("entryInjected")
    public int entryInjected;

    @JsonProperty("entryMethodIdentityDupSkipped")
    public int entryMethodIdentityDupSkipped;

    @JsonProperty("entryUnresolved")
    public int entryUnresolved;

    @JsonProperty("entryNoBodySkipped")
    public int entryNoBodySkipped;

    @JsonProperty("supplementalEntriesInjected")
    public int supplementalEntriesInjected;

    @JsonProperty("supplementalEntriesSkipped")
    public int supplementalEntriesSkipped;

    @JsonProperty("serviceFallbackClasses")
    public int serviceFallbackClasses;

    @JsonProperty("serviceFallbackMethodsInjected")
    public int serviceFallbackMethodsInjected;

    @JsonProperty("capturedTaintFlows")
    public Integer capturedTaintFlows;

    @JsonProperty("sourceRaw")
    public int sourceRaw;

    @JsonProperty("sourceUnique")
    public int sourceUnique;

    @JsonProperty("sourceDuplicate")
    public int sourceDuplicate;

    public Map<String, Object> asMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("springAnalysis", springAnalysis);
        m.put("taintCallSiteMode", taintCallSiteMode);
        m.put("springServiceEntryFallback", springServiceEntryFallback);
        m.put("persistentSourceMode", persistentSourceMode);
        m.put("persistentSourceEnabled", persistentSourceEnabled);
        if (persistentSourceDisableReason != null) {
            m.put("persistentSourceDisableReason", persistentSourceDisableReason);
        }
        m.put("persistentSourceMaxPatterns", persistentSourceMaxPatterns);
        m.put("persistentSourceMaxSupplementalEntries", persistentSourceMaxSupplementalEntries);
        m.put("apiParamSourcesRaw", apiParamSourcesRaw);
        m.put("apiParamSourcesUnique", apiParamSourcesUnique);
        m.put("explicitRuleSourcesUnique", explicitRuleSourcesUnique);
        m.put("persistentPatternsRaw", persistentPatternsRaw);
        m.put("persistentPatternsEmitted", persistentPatternsEmitted);
        m.put("persistentPatternsTruncated", persistentPatternsTruncated);
        m.put("persistentDirectSources", persistentDirectSources);
        m.put("persistentAccessorSources", persistentAccessorSources);
        m.put("supplementalEntriesRaw", supplementalEntriesRaw);
        m.put("supplementalEntriesEmitted", supplementalEntriesEmitted);
        m.put("supplementalEntriesTruncated", supplementalEntriesTruncated);
        m.put("entryCandidates", entryCandidates);
        m.put("entryInjected", entryInjected);
        m.put("entryMethodIdentityDupSkipped", entryMethodIdentityDupSkipped);
        m.put("entryUnresolved", entryUnresolved);
        m.put("entryNoBodySkipped", entryNoBodySkipped);
        m.put("supplementalEntriesInjected", supplementalEntriesInjected);
        m.put("supplementalEntriesSkipped", supplementalEntriesSkipped);
        m.put("serviceFallbackClasses", serviceFallbackClasses);
        m.put("serviceFallbackMethodsInjected", serviceFallbackMethodsInjected);
        if (capturedTaintFlows != null) {
            m.put("capturedTaintFlows", capturedTaintFlows);
        }
        m.put("sourceRaw", sourceRaw);
        m.put("sourceUnique", sourceUnique);
        m.put("sourceDuplicate", sourceDuplicate);
        return m;
    }

    public void write(Path workspaceDir) {
        try {
            Path out = workspaceDir.resolve("expansion-metrics.json");
            MAPPER.writerWithDefaultPrettyPrinter().writeValue(out.toFile(), this);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to write expansion-metrics.json", e);
        }
    }
}
