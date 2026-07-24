package com.jbytescanner.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class Config {
    /** Version of the bundled rule schema/content last merged into this file. */
    @JsonProperty("rules_version")
    private int rulesVersion;

    @JsonProperty("config")
    private ScanConfig scanConfig;

    @JsonProperty("sources")
    private List<SourceRule> sources = new ArrayList<>();

    @JsonProperty("sinks")
    private List<SinkRule> sinks = new ArrayList<>();

    @JsonProperty("transfers")
    private List<TransferRule> transfers = new ArrayList<>();
}
