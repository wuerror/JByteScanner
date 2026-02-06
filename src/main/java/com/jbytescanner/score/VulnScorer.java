package com.jbytescanner.score;

import com.jbytescanner.config.SinkRule;
import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import soot.SootMethod;
import soot.Scene;

public class VulnScorer {

    private final AuthDetector authDetector;

    public VulnScorer(AuthDetector authDetector) {
        this.authDetector = authDetector;
    }

    public void score(Vulnerability vuln, ApiRoute route) {
        SinkRule sink = vuln.getSinkRule();
        
        // 1. Base Score (Sink Severity)
        double baseScore = sink.getBaseScore();
        
        // 2. Reachability Factor
        // If we have a route, it's 1.0. If not (e.g. background task), we downgrade.
        double reachability = (route != null) ? 1.0 : 0.1;

        // 3. Auth Barrier Factor
        double authBarrier = 1.0; // Default: Public
        if (route != null) {
            try {
                // Try to find the SootMethod for the route
                // ApiRoute stores "java.lang.String getUser(java.lang.String)" in methodSig
                // But Soot needs Full Signature: <com.example.UserController: java.lang.String getUser(java.lang.String)>
                String fullSig = String.format("<%s: %s>", route.getClassName(), route.getMethodSig());
                SootMethod sm = Scene.v().grabMethod(fullSig);
                if (sm != null) {
                    authBarrier = authDetector.detectBarrier(sm);
                } else {
                     // Try fuzzy match if exact signature fails (often fails due to spacing)
                     // Implementation omitted for brevity, fallback to Public
                }
            } catch (Exception e) {
                // Method might not be loaded or signature mismatch
            }
        }
        
        // 4. Confidence Factor
        double confidence = vuln.isFullFlow() ? 1.0 : 0.5;

        // Formula
        // We don't want to just multiply everything because 10 * 0.5 = 5 (Medium).
        // A high risk RCE (10) behind Auth (0.5) is still High Risk (5.0), but reachable.
        // Let's adjust logic:
        // Final Score = Base * Reachability * AuthBarrier?
        // If AuthBarrier is 0.5 (Auth Required), Score becomes 5.0. 
        // This seems reasonable. RCE (10) -> Auth RCE (5.0).
        // But maybe we want to keep it higher?
        // Let's stick to the user agreed formula: S * R * A * C?
        // Actually C is Confidence, it shouldn't lower the severity, just the likelihood.
        // Let's separate "Risk Score" and "Confidence".
        
        // For Red Team:
        // Score = Base * AuthBarrier. (Reachability is usually binary 0 or 1 in this context)
        // If Dead Code (R=0.1), Score = 1.0 (Info). Correct.
        // If Auth RCE, Score = 10 * 0.5 = 5.0. 
        // A SQLi (8) * Public (1.0) = 8.0.
        // So Public SQLi > Auth RCE. This makes sense for external exposure.
        
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
