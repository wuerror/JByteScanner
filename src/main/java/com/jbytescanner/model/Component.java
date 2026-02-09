package com.jbytescanner.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Component {
    private String groupId;
    private String artifactId;
    private String version;
    private String sourcePath;
    
    @Override
    public String toString() {
        return (groupId != null ? groupId : "?") + ":" + artifactId + ":" + (version != null ? version : "?");
    }
}
