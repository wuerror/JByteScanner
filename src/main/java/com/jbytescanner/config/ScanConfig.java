package com.jbytescanner.config;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import lombok.AccessLevel;
import lombok.Data;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Data
public class ScanConfig {
    @JsonProperty("max_depth")
    private int maxDepth = 10;

    @JsonProperty("scan_packages")
    private List<String> scanPackages = new ArrayList<>();

    /**
     * Packages used for finding provenance (default = scan_packages).
     * Sink containers outside these packages are weak-sink filtered / terminal demoted.
     */
    @JsonProperty("finding_packages")
    private List<String> findingPackages = new ArrayList<>();

    @JsonProperty("noise_filter")
    private NoiseFilterConfig noiseFilter;

    @JsonProperty("auth_config")
    private AuthConfig authConfig;

    /** Enable Tai-e 0.5.4 built-in Spring DI and Web endpoint modeling. */
    @JsonProperty("spring_analysis")
    private boolean springAnalysis = true;

    /**
     * Match taint sources, sinks, and transfers at reachable call sites even when
     * pointer analysis cannot resolve a concrete callee (for example interface-typed
     * Web parameters such as MultipartFile).
     */
    @JsonProperty("taint_call_site_mode")
    private boolean taintCallSiteMode = true;

    /** Add public methods of concrete Spring @Service classes as fallback entries. */
    @JsonProperty("spring_service_entry_fallback")
    private boolean springServiceEntryFallback = false;

    /**
     * Persistent/cache typed-source inference mode: {@code off}, {@code on}, or {@code auto}.
     * Legacy boolean values in rules.yaml are accepted ({@code true}->{@code on}, {@code false}->{@code off}).
     * Default {@code on}: common small/medium projects benefit from second-order flows.
     */
    @Setter(AccessLevel.NONE)
    @JsonProperty("persistent_source_analysis")
    private String persistentSourceAnalysis = "on";

    /**
     * Cap on raw typed persistent-read patterns before truncation (0 = unlimited).
     */
    @JsonProperty("persistent_source_max_patterns")
    private int persistentSourceMaxPatterns = 10000;

    /**
     * Cap on supplemental entry methods derived from persistent reads (0 = unlimited).
     */
    @JsonProperty("persistent_source_max_supplemental_entries")
    private int persistentSourceMaxSupplementalEntries = 5000;

    /**
     * For {@code auto} mode: disable persistent analysis when app classpath entry count
     * exceeds this threshold (target+dep jars/dirs). Ecology-scale projects trip this.
     */
    @JsonProperty("persistent_source_auto_max_app_classpath")
    private int persistentSourceAutoMaxAppClasspath = 120;

    /**
     * Resource budget for isolated Tai-e worker JVM (heap, timeout, GC, heap dump).
     * When null, defaults from {@link ResourceBudget} are used.
     */
    @JsonProperty("resource_budget")
    private ResourceBudget resourceBudget;

    public ResourceBudget getResourceBudget() {
        if (resourceBudget == null) {
            resourceBudget = new ResourceBudget();
        }
        return resourceBudget;
    }

    public List<String> getScanPackages() {
        if (scanPackages == null) {
            scanPackages = new ArrayList<>();
        }
        return scanPackages;
    }

    public List<String> getFindingPackages() {
        if (findingPackages == null) {
            findingPackages = new ArrayList<>();
        }
        return findingPackages;
    }

    public NoiseFilterConfig getNoiseFilter() {
        if (noiseFilter == null) {
            noiseFilter = new NoiseFilterConfig();
        }
        return noiseFilter;
    }

    /**
     * Accepts boolean legacy values and string modes from YAML.
     */
    public void setPersistentSourceAnalysis(String value) {
        setPersistentSourceAnalysis((Object) value);
    }

    @JsonSetter("persistent_source_analysis")
    public void setPersistentSourceAnalysis(Object value) {
        if (value == null) {
            this.persistentSourceAnalysis = "on";
            return;
        }
        if (value instanceof Boolean b) {
            this.persistentSourceAnalysis = b ? "on" : "off";
            return;
        }
        String s = value.toString().trim().toLowerCase(Locale.ROOT);
        if ("true".equals(s) || "yes".equals(s) || "1".equals(s)) {
            this.persistentSourceAnalysis = "on";
        } else if ("false".equals(s) || "no".equals(s) || "0".equals(s)) {
            this.persistentSourceAnalysis = "off";
        } else if ("on".equals(s) || "off".equals(s) || "auto".equals(s)) {
            this.persistentSourceAnalysis = s;
        } else {
            this.persistentSourceAnalysis = "on";
        }
    }

    @JsonIgnore
    public String getPersistentSourceMode() {
        if (persistentSourceAnalysis == null || persistentSourceAnalysis.isBlank()) {
            return "on";
        }
        return persistentSourceAnalysis.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Legacy boolean accessor: true when mode is {@code on}, or {@code auto} without
     * classpath context (callers that need auto should use {@link #resolvePersistentSourceEnabled(int)}).
     */
    @JsonIgnore
    public boolean isPersistentSourceAnalysis() {
        String mode = getPersistentSourceMode();
        return !"off".equals(mode);
    }

    /**
     * Resolve whether persistent source analysis should run for this classpath size.
     *
     * @param appClasspathCount number of target+dep application classpath entries
     * @return enabled, mode used, and optional disable reason
     */
    public PersistentSourceDecision resolvePersistentSourceEnabled(int appClasspathCount) {
        String mode = getPersistentSourceMode();
        int maxPatterns = Math.max(0, persistentSourceMaxPatterns);
        int maxSupp = Math.max(0, persistentSourceMaxSupplementalEntries);
        if ("off".equals(mode)) {
            return new PersistentSourceDecision(false, mode, "mode=off", maxPatterns, maxSupp);
        }
        if ("auto".equals(mode)) {
            int threshold = persistentSourceAutoMaxAppClasspath > 0
                    ? persistentSourceAutoMaxAppClasspath
                    : 120;
            if (appClasspathCount > threshold) {
                return new PersistentSourceDecision(false, mode,
                        "auto: appClasspathCount=" + appClasspathCount + " > " + threshold,
                        maxPatterns, maxSupp);
            }
            return new PersistentSourceDecision(true, mode,
                    "auto: appClasspathCount=" + appClasspathCount + " <= " + threshold,
                    maxPatterns, maxSupp);
        }
        // on (default)
        return new PersistentSourceDecision(true, "on", null, maxPatterns, maxSupp);
    }

    public record PersistentSourceDecision(
            boolean enabled,
            String mode,
            String reason,
            int maxPatterns,
            int maxSupplementalEntries
    ) {
    }
}
