package com.jbytescanner.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;
import java.util.ArrayList;

@Data
public class Config {
    @JsonProperty("config")
    private ScanConfig scanConfig;

    @JsonProperty("sources")
    private List<SourceRule> sources = new ArrayList<>();

    @JsonProperty("sinks")
    private List<SinkRule> sinks = new ArrayList<>();
}
