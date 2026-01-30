package com.jbytescanner.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class SinkRule {
    @JsonProperty("type")
    private String type; // e.g., "method"

    @JsonProperty("vuln_type")
    private String vulnType; // e.g., "RCE", "SQLi"

    @JsonProperty("signature")
    private String signature;
}
