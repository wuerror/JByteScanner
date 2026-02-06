package com.jbytescanner.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.ArrayList;
import java.util.List;

@Data
public class AuthConfig {
    @JsonProperty("blocking_annotations")
    private List<String> blockingAnnotations = new ArrayList<>();

    @JsonProperty("bypass_annotations")
    private List<String> bypassAnnotations = new ArrayList<>();
}
