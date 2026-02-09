package com.jbytescanner.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;

@Data
public class Gadget {
    private String name;
    private String description;
    
    @JsonProperty("class")
    private String className; 
    
    private List<Dependency> dependencies;

    @Data
    public static class Dependency {
        private String group;
        private String artifact;
        private String version;
        private String raw;
    }
}
