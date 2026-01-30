package com.jbytescanner.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class SourceRule {
    @JsonProperty("type")
    private String type; // e.g., "annotation", "method"

    @JsonProperty("value")
    private String value; // For annotation type

    @JsonProperty("signature")
    private String signature; // For method type
}
