package com.jbytescanner.core;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One classpath artifact (JAR/WAR/class directory) after preflight inspection.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ArtifactDescriptor {

    public enum Role {
        TARGET_APP,
        DEP_APP,
        LIBRARY,
        DROPPED_DUPLICATE,
        EXTRACTED_APP
    }

    @JsonProperty("path")
    public String path;

    @JsonProperty("fileName")
    public String fileName;

    @JsonProperty("sha256")
    public String sha256;

    @JsonProperty("size")
    public long size;

    @JsonProperty("manifestVersion")
    public String manifestVersion;

    @JsonProperty("artifactId")
    public String artifactId;

    @JsonProperty("classCount")
    public int classCount;

    @JsonProperty("applicationClassCount")
    public int applicationClassCount;

    @JsonProperty("applicationClassRatio")
    public double applicationClassRatio;

    @JsonProperty("duplicateClassCount")
    public int duplicateClassCount;

    @JsonProperty("packageHistogram")
    public Map<String, Integer> packageHistogram = new LinkedHashMap<>();

    @JsonProperty("selectedRole")
    public Role selectedRole;

    @JsonProperty("selectionReason")
    public String selectionReason;

    @JsonProperty("extractedTo")
    public String extractedTo;

    @JsonProperty("sourceArtifact")
    public String sourceArtifact;
}
