package com.jbytescanner.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;
import java.util.ArrayList;

@Data
public class ScanConfig {
    @JsonProperty("max_depth")
    private int maxDepth = 10;

    @JsonProperty("scan_packages")
    private List<String> scanPackages = new ArrayList<>();

    @JsonProperty("auth_config")
    private AuthConfig authConfig;

    public List<String> getScanPackages() {
        if (scanPackages == null) {
            scanPackages = new ArrayList<>();
        }
        return scanPackages;
    }
}
