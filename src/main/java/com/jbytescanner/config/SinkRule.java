package com.jbytescanner.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class SinkRule {
    @JsonProperty("type")
    private String type; // e.g., "method"

    @JsonProperty("vuln_type")
    private String vulnType; // e.g., "RCE", "SQLi"

    @JsonProperty("category")
    private String category; // e.g., "code-exec", "cmd-exec", "jndi"

    @JsonProperty("severity")
    private Double severity; // 0.0 - 10.0 override

    @JsonProperty("signature")
    private String signature;
    
    // Computed property - ignore for serialization/deserialization
    @com.fasterxml.jackson.annotation.JsonIgnore
    public double getBaseScore() {
        if (severity != null) return severity;
        if (category == null) return 5.0; // Default Medium

        switch (category.toLowerCase().trim()) {
            case "code-exec": return 10.0;
            case "cmd-exec": return 9.5;
            case "jndi": return 9.0;
            case "deserialization": return 8.5;
            case "sqli": return 8.0;
            case "ssrf": return 7.5;
            case "file-write": return 7.0;
            case "file-read": return 6.0;
            case "path_traversal": return 6.0; // Added alias
            case "xxe": return 6.0;
            case "xss": return 4.0;
            default: return 5.0;
        }
    }
}
