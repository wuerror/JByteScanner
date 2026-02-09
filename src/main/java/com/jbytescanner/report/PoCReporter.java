package com.jbytescanner.report;

import com.jbytescanner.model.ApiRoute;
import com.jbytescanner.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class PoCReporter {
    private static final Logger logger = LoggerFactory.getLogger(PoCReporter.class);
    private final File workspaceDir;

    public PoCReporter(File workspaceDir) {
        this.workspaceDir = workspaceDir;
    }

    public void generate(List<Vulnerability> vulns, List<ApiRoute> routes) {
        if (vulns.isEmpty()) return;

        PoCGenerator generator = new PoCGenerator();
        List<String> output = new ArrayList<>();
        
        output.add("### JByteScanner Generated PoCs ###");
        output.add("### Import these into Burp Suite Repeater ###\n");
        
        for (Vulnerability vuln : vulns) {
            // Find corresponding route
            ApiRoute route = findRoute(routes, vuln.getSourceMethod());
            if (route != null) {
                try {
                    String poc = generator.generate(vuln, route);
                    
                    output.add("==================================================");
                    output.add(String.format("Vulnerability: %s", vuln.getType()));
                    output.add(String.format("Sink: %s", vuln.getSinkMethod()));
                    output.add(String.format("Route: %s %s", route.getHttpMethod(), route.getPath()));
                    output.add("==================================================");
                    output.add(poc);
                    output.add("\n");
                } catch (Exception e) {
                    logger.warn("Failed to generate PoC for {}", vuln.getType(), e);
                }
            }
        }

        File reportFile = new File(workspaceDir, "generated_pocs.txt");
        try {
            Files.write(reportFile.toPath(), output);
            logger.info("PoC Report generated at: {}", reportFile.getAbsolutePath());
        } catch (IOException e) {
            logger.error("Failed to write PoC report", e);
        }
    }
    
    private ApiRoute findRoute(List<ApiRoute> routes, String methodSig) {
        if (methodSig == null) return null;
        for (ApiRoute r : routes) {
            // methodSig: <com.example.Controller: void test(String)>
            // route class: com.example.Controller
            // route methodSig: void test(java.lang.String)
            
            // Simple check: Class name must match
            if (methodSig.contains(r.getClassName())) {
                // Check method name
                // Extract method name from full sig
                // <com...: ret methodName(args)>
                String[] parts = methodSig.split(" ");
                if (parts.length > 0) {
                     String nameWithParen = parts[parts.length - 1];
                     String name = nameWithParen.split("\\(")[0];
                     if (r.getMethodSig().contains(name + "(")) {
                         return r;
                     }
                }
            }
        }
        return null;
    }
}
