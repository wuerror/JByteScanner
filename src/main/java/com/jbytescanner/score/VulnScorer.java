package com.jbytescanner.score;

import com.jbytescanner.config.SinkRule;
import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import pascal.taie.World;
import pascal.taie.language.classes.JMethod;

public class VulnScorer {

    private final AuthDetector authDetector;

    public VulnScorer(AuthDetector authDetector) {
        this.authDetector = authDetector;
    }

    public void score(Vulnerability vuln, ApiRoute route) {
        SinkRule sink = vuln.getSinkRule();
        
        // 1. Base Score (Sink Severity)
        double baseScore = sink != null ? sink.getBaseScore() : 5.0;
        
        // 2. Reachability Factor
        // If we have a route, it's 1.0. If not (e.g. background task), we downgrade.
        double reachability = (route != null) ? 1.0 : 0.1;

        // 3. Auth Barrier Factor
        double authBarrier = 1.0; // Default: Public
        if (route != null) {
            try {
                // Try to find the JMethod for the route
                // ApiRoute stores "java.lang.String getUser(java.lang.String)" in methodSig
                String fullSig = String.format("<%s: %s>", route.getClassName(), route.getMethodSig());
                JMethod sm = World.get().getClassHierarchy().getMethod(fullSig);
                if (sm != null) {
                    authBarrier = authDetector.detectBarrier(sm);
                } 
            } catch (Exception e) {
                // Method might not be loaded or signature mismatch
            }
        }
        
        // 4. Confidence Factor
        double confidence = vuln.isFullFlow() ? 1.0 : 0.5;

        double finalScore = baseScore * reachability * authBarrier;
        
        vuln.setScore(finalScore);
        vuln.setConfidenceScore(confidence);
        
        // Set Text Risk
        if (finalScore >= 9.0) vuln.setRiskLevel("CRITICAL");
        else if (finalScore >= 7.0) vuln.setRiskLevel("HIGH");
        else if (finalScore >= 4.0) vuln.setRiskLevel("MEDIUM");
        else if (finalScore >= 1.0) vuln.setRiskLevel("LOW");
        else vuln.setRiskLevel("INFO");
    }
}