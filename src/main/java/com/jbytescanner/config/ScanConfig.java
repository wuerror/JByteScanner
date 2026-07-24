package com.jbytescanner.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class ScanConfig {
    @JsonProperty("max_depth")
    private int maxDepth = 10;

    @JsonProperty("scan_packages")
    private List<String> scanPackages = new ArrayList<>();

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

    /** Infer typed taint sources from cache APIs shaped like Object get(String, Class). */
    @JsonProperty("persistent_source_analysis")
    private boolean persistentSourceAnalysis = true;

    public List<String> getScanPackages() {
        if (scanPackages == null) {
            scanPackages = new ArrayList<>();
        }
        return scanPackages;
    }
}
