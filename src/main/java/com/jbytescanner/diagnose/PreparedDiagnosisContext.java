package com.jbytescanner.diagnose;

import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.config.ResourceBudget;
import com.jbytescanner.model.ApiRoute;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Host-side inputs prepared before targeted diagnosis. Kept separate from the
 * CLI so deterministic stages can be tested without loading a deployment.
 */
public record PreparedDiagnosisContext(
        String targetPath,
        Path workspace,
        List<String> targetAppJars,
        List<String> depAppJars,
        List<String> libJars,
        ConfigManager configManager,
        List<ApiRoute> routes,
        Path apiFile,
        ResourceBudget budget
) {
    public PreparedDiagnosisContext {
        targetAppJars = copy(targetAppJars);
        depAppJars = copy(depAppJars);
        libJars = copy(libJars);
        routes = routes == null ? List.of() : List.copyOf(routes);
    }

    public List<String> allAppJars() {
        List<String> all = new ArrayList<>();
        all.addAll(targetAppJars);
        all.addAll(depAppJars);
        return all;
    }

    public List<String> allArtifacts() {
        List<String> all = new ArrayList<>();
        all.addAll(targetAppJars);
        all.addAll(depAppJars);
        all.addAll(libJars);
        return all;
    }

    private static List<String> copy(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}
