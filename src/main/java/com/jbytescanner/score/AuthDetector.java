package com.jbytescanner.score;

import com.jbytescanner.config.AuthConfig;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.annotation.Annotation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class AuthDetector {
    private static final Logger logger = LoggerFactory.getLogger(AuthDetector.class);

    private static final List<String> DEFAULT_BLOCKING_KEYWORDS = Arrays.asList(
        "auth", "secur", "login", "perm", "guard", "role", "admin", "user"
    );
    
    private static final List<String> DEFAULT_BYPASS_KEYWORDS = Arrays.asList(
        "public", "anon", "open", "permitall", "ignore"
    );

    private final AuthConfig authConfig;

    public AuthDetector(AuthConfig authConfig) {
        this.authConfig = authConfig;
    }

    /**
     * Detects Auth Barrier for a given method signature.
     * Returns a factor from 0.0 (Strong Auth) to 1.0 (No Auth).
     */
    public double detectBarrier(JMethod method) {
        if (method == null) return 1.0;

        // Check Method Annotations
        double methodScore = checkAnnotations(method.getAnnotations());
        if (methodScore < 1.0) return methodScore; // Explicit auth on method

        // Check Class Annotations
        double classScore = checkAnnotations(method.getDeclaringClass().getAnnotations());
        return classScore;
    }

    private double checkAnnotations(Collection<Annotation> annotations) {
        if (annotations == null) return 1.0;
        
        for (Annotation tag : annotations) {
            String className = tag.getType(); 
            // e.g. com.example.Auth
            String simpleName = className.substring(className.lastIndexOf('.') + 1).toLowerCase();
            
            // 1. Check Explicit Configuration
            if (authConfig != null) {
                if (authConfig.getBlockingAnnotations().contains(className)) return 0.5; // Custom Auth
                if (authConfig.getBypassAnnotations().contains(className)) return 1.0;   // Custom Bypass
            }

            // 2. Fuzzy Matching (Heuristic)
            // Priority: Bypass Keywords > Blocking Keywords
            
            for (String keyword : DEFAULT_BYPASS_KEYWORDS) {
                if (simpleName.contains(keyword)) return 1.0;
            }

            for (String keyword : DEFAULT_BLOCKING_KEYWORDS) {
                if (simpleName.contains(keyword)) {
                    // Special check for "Authorities" or similar which might be tricky
                    // But generally if it says "Auth", it's a barrier.
                    return 0.5; // Auth Required
                }
            }
        }
        return 1.0; // No barrier found
    }
}
