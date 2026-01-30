package com.jbytescanner.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ApiRoute {
    private String httpMethod; // GET, POST, etc.
    private String path;       // /api/v1/user
    private String className;  // com.example.UserController
    private String methodSig;  // java.lang.String getUser(java.lang.String)

    @Override
    public String toString() {
        return String.format("%s %s %s %s", 
                httpMethod != null ? httpMethod : "ALL", 
                path, 
                className, 
                methodSig);
    }
}
