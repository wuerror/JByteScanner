package com.jbytescanner.report;

import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PoCReporter {
    private static final Logger logger = LoggerFactory.getLogger(PoCReporter.class);
    private static final Pattern SOURCE_SIG = Pattern.compile(
            "^<([^:]+):\\s*([\\w.$\\[\\]]+)\\s+([\\w$<>]+\\([^)]*\\))>$");

    private final File workspaceDir;

    public PoCReporter(File workspaceDir) {
        this.workspaceDir = workspaceDir;
    }

    public void generate(List<Vulnerability> vulns, List<ApiRoute> routes) {
        if (vulns == null || vulns.isEmpty()) {
            return;
        }

        PoCGenerator generator = new PoCGenerator();
        List<String> output = new ArrayList<>();
        output.add("### JByteScanner Generated PoCs ###");
        output.add("### Import these into Burp Suite Repeater ###\n");

        int matched = 0;
        int unmatched = 0;
        int failed = 0;
        for (Vulnerability vuln : vulns) {
            ApiRoute route = findRoute(routes, vuln.getSourceMethod());
            if (route == null) {
                unmatched++;
                logger.warn("No API route matched for PoC source: {}", vuln.getSourceMethod());
                output.add("==================================================");
                output.add(String.format("Vulnerability: %s (no matching route)", vuln.getType()));
                output.add(String.format("Source: %s", vuln.getSourceMethod()));
                output.add(String.format("Sink: %s", vuln.getSinkMethod()));
                output.add("==================================================");
                output.add("# Could not map source method to discovery route; PoC omitted.");
                output.add("\n");
                continue;
            }
            try {
                String poc = generator.generate(vuln, route);
                matched++;
                output.add("==================================================");
                output.add(String.format("Vulnerability: %s", vuln.getType()));
                output.add(String.format("Sink: %s", vuln.getSinkMethod()));
                output.add(String.format("Route: %s %s", route.getHttpMethod(), route.getPath()));
                output.add(String.format("Source: %s", vuln.getSourceMethod()));
                output.add("==================================================");
                output.add(poc);
                output.add("\n");
            } catch (Exception e) {
                failed++;
                logger.warn("Failed to generate PoC for {} ({})", vuln.getType(),
                        vuln.getSourceMethod(), e);
                output.add("==================================================");
                output.add(String.format("Vulnerability: %s (generation failed)", vuln.getType()));
                output.add(String.format("Source: %s", vuln.getSourceMethod()));
                output.add(String.format("Error: %s", e.toString()));
                output.add("==================================================\n");
            }
        }
        logger.info("PoC generation: matchedRoutes={}, unmatchedSources={}, generateFailures={}",
                matched, unmatched, failed);

        File reportFile = new File(workspaceDir, "generated_pocs.txt");
        try {
            Files.writeString(reportFile.toPath(), String.join("\n", output), StandardCharsets.UTF_8);
            logger.info("PoC Report generated at: {}", reportFile.getAbsolutePath());
        } catch (IOException e) {
            logger.error("Failed to write PoC report", e);
        }
    }

    /**
     * Match vulnerability source method signature to discovery route.
     * Source: {@code <pkg.Class: ret name(args)>}
     * Route: className + methodSig {@code ret name(args)}
     */
    static ApiRoute findRoute(List<ApiRoute> routes, String methodSig) {
        if (methodSig == null || routes == null || routes.isEmpty()) {
            return null;
        }
        String className = null;
        String methodName = null;
        String methodWithArgs = null;
        Matcher m = SOURCE_SIG.matcher(methodSig.trim());
        if (m.find()) {
            className = m.group(1);
            methodWithArgs = m.group(3);
            int paren = methodWithArgs.indexOf('(');
            methodName = paren > 0 ? methodWithArgs.substring(0, paren) : methodWithArgs;
        } else {
            for (ApiRoute r : routes) {
                if (r.getClassName() != null && methodSig.contains(r.getClassName())
                        && r.getMethodSig() != null) {
                    String shortName = r.getMethodSig().replaceAll("\\(.*\\)", "");
                    String nameOnly = shortName.contains(" ")
                            ? shortName.substring(shortName.lastIndexOf(' ') + 1)
                            : shortName;
                    if (methodSig.contains(nameOnly + "(")) {
                        return r;
                    }
                }
            }
            return null;
        }

        ApiRoute best = null;
        for (ApiRoute r : routes) {
            if (r.getClassName() == null || r.getMethodSig() == null) {
                continue;
            }
            if (!r.getClassName().equals(className) && !methodSig.contains(r.getClassName())) {
                continue;
            }
            if (r.getMethodSig().equals(methodWithArgs)
                    || r.getMethodSig().endsWith(" " + methodWithArgs)
                    || r.getMethodSig().contains(methodName + "(")) {
                if (r.getMethodSig().equals(methodWithArgs)
                        || r.getMethodSig().endsWith(" " + methodWithArgs)) {
                    return r;
                }
                if (best == null) {
                    best = r;
                }
            }
        }
        return best;
    }
}
