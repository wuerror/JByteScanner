package com.jbytescanner.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ApiRoute {
    private String httpMethod; // GET, POST, etc.
    private String path;       // /api/v1/user
    private String className;  // com.example.UserController
    private String methodSig;  // java.lang.String getUser(java.lang.String)
    
    // Phase 8.3: Metadata for PoC Generation
    private List<String> parameters; // Format: "name:type"
    private Map<String, String> paramAnnotations; // Format: "paramName" -> "AnnotationType" (e.g., "user" -> "RequestBody")
    private String contentType; // e.g., "application/json", "application/x-www-form-urlencoded"

    // Legacy Constructor for compatibility
    public ApiRoute(String httpMethod, String path, String className, String methodSig) {
        this.httpMethod = httpMethod;
        this.path = path;
        this.className = className;
        this.methodSig = methodSig;
    }

    @Override
    public String toString() {
        String base = String.format("%s %s %s %s", 
                httpMethod != null ? httpMethod : "ALL", 
                path, 
                className, 
                methodSig);
        
        // Phase 8.3: Append Metadata in JSON format for persistence
        if (contentType != null || (parameters != null && !parameters.isEmpty())) {
            StringBuilder json = new StringBuilder();
            json.append(" | {");
            boolean hasPrev = false;
            
            if (contentType != null) {
                json.append("\"contentType\":\"").append(contentType).append("\"");
                hasPrev = true;
            }
            
            if (parameters != null && !parameters.isEmpty()) {
                if (hasPrev) json.append(", ");
                json.append("\"params\":[");
                for (int i = 0; i < parameters.size(); i++) {
                    if (i > 0) json.append(",");
                    json.append("\"").append(parameters.get(i)).append("\"");
                }
                json.append("]");
                hasPrev = true;
            }
            
            if (paramAnnotations != null && !paramAnnotations.isEmpty()) {
                if (hasPrev) json.append(", ");
                json.append("\"annotations\":{");
                int i = 0;
                for (Map.Entry<String, String> e : paramAnnotations.entrySet()) {
                    if (i > 0) json.append(",");
                    json.append("\"").append(e.getKey()).append("\":\"").append(e.getValue()).append("\"");
                    i++;
                }
                json.append("}");
            }
            
            json.append("}");
            return base + json.toString();
        }
        
        return base;
    }
}
