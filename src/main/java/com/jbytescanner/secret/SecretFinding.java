package com.jbytescanner.secret;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SecretFinding {
    private String type; // e.g., "Hardcoded Password", "AWS Key", "JWT"
    private String location; // Class name or File path
    private String matchedValue; // The secret itself (careful with logging)
    private String context; // Surrounding text or key name
    private String severity; // HIGH, MEDIUM, LOW
}
