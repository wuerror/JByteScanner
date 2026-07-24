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

    /** Tai-e source index (for example result, base, or a numeric parameter index). */
    @JsonProperty("index")
    private Object index;

    /** Optional concrete taint-object type when the declared API type is too generic. */
    @JsonProperty("taint_type")
    private String taintType;
}
