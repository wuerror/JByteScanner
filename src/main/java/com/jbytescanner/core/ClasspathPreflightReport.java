package com.jbytescanner.core;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ClasspathPreflightReport {

    @JsonProperty("generatedAt")
    public String generatedAt;

    @JsonProperty("scanPackages")
    public List<String> scanPackages = new ArrayList<>();

    @JsonProperty("targetAppCount")
    public int targetAppCount;

    @JsonProperty("depAppCount")
    public int depAppCount;

    @JsonProperty("libraryCount")
    public int libraryCount;

    @JsonProperty("droppedDuplicateCount")
    public int droppedDuplicateCount;

    @JsonProperty("mixedJarExtractions")
    public int mixedJarExtractions;

    @JsonProperty("warnings")
    public List<String> warnings = new ArrayList<>();

    @JsonProperty("duplicateClassGroups")
    public int duplicateClassGroups;

    @JsonProperty("artifacts")
    public List<ArtifactDescriptor> artifacts = new ArrayList<>();

    @JsonProperty("versionSelections")
    public List<Map<String, String>> versionSelections = new ArrayList<>();

    public void addWarning(String warning) {
        if (warning != null && !warning.isBlank()) {
            warnings.add(warning);
        }
    }

    public void addVersionSelection(String artifactId, String chosenPath, String reason) {
        Map<String, String> row = new LinkedHashMap<>();
        row.put("artifactId", artifactId);
        row.put("chosenPath", chosenPath);
        row.put("reason", reason);
        versionSelections.add(row);
    }
}
