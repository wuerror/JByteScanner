package com.jbytescanner;

import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.core.JarLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.util.concurrent.Callable;
import java.util.List;

@Command(name = "JByteScanner", mixinStandardHelpOptions = true, version = "1.0",
        description = "Java Bytecode Security Scanner based on Soot")
public class JByteScanner implements Callable<Integer> {
    private static final Logger logger = LoggerFactory.getLogger(JByteScanner.class);

    @Parameters(index = "0", description = "Target directory or JAR file to scan")
    private String targetPath;

    @Option(names = {"-c", "--config"}, description = "Path to custom configuration file (optional)")
    private String configPath;

    @Option(names = {"--filter-annotation"}, description = "Filter APIs by annotation keyword (e.g. 'Anonymous')")
    private List<String> filterAnnotations;

    @Option(names = {"-m", "--mode"}, defaultValue = "scan", description = "Execution mode: 'api' (Asset Discovery only) or 'scan' (Full Vulnerability Scan)")
    private String mode;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new JByteScanner()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        System.out.println("==========================================");
        System.out.println("   JByteScanner - Next Gen Static Analysis");
        System.out.println("==========================================");

        // 0. Determine Workspace Directory (.jbytescanner)
        File targetFile = new File(targetPath);
        File projectRoot = targetFile.isDirectory() ? targetFile : targetFile.getParentFile();
        File workspaceDir = new File(projectRoot, ".jbytescanner");
        
        if (!workspaceDir.exists()) {
            boolean created = workspaceDir.mkdirs();
            if (created) {
                System.out.println("Initialized workspace at: " + workspaceDir.getAbsolutePath());
            }
        }

        // 1. Initialize Configuration (Project Specific)
        ConfigManager configManager = new ConfigManager();
        configManager.init(workspaceDir);

        // 2. Load JARs (Now separated into App and Lib jars, with Promotion logic)
        JarLoader jarLoader = new JarLoader();
        List<String> scanPackages = configManager.getConfig().getScanConfig().getScanPackages();
        
        // Load raw jars first
        JarLoader.LoadedJars loadedJars = jarLoader.loadJars(targetPath, scanPackages);
        
        // 2.5 Smart Package Inference (If no scan_packages defined)
        if (scanPackages == null || scanPackages.isEmpty()) {
            logger.info("No scan_packages defined in rules.yaml. Attempting to infer base package...");
            
            // Infer from ALL app jars initially identified
            List<String> initialAppJars = new java.util.ArrayList<>(loadedJars.targetAppJars);
            initialAppJars.addAll(loadedJars.depAppJars);
            
            String inferredPackage = jarLoader.inferBasePackage(initialAppJars);
            
            if (inferredPackage != null) {
                logger.info("Inferred Base Package: {}", inferredPackage);
                configManager.updateScanPackage(inferredPackage);
                // Reload scanPackages variable
                scanPackages = configManager.getConfig().getScanConfig().getScanPackages();
                
                // CRITICAL: Re-run loadJars to correctly classify Target vs Lib based on new package
                // This ensures strict isolation works correctly
                logger.info("Re-classifying JARs based on inferred package...");
                loadedJars = jarLoader.loadJars(targetPath, scanPackages);
                
            } else {
                logger.warn("Could not infer base package. Analysis will cover ALL application classes (slower).");
            }
        }
        
        System.out.println("------------------------------------------");
        System.out.println("Target: " + targetPath);
        System.out.println("Workspace: " + workspaceDir.getAbsolutePath());
        System.out.println("Target App Jars (Analysis Scope): " + loadedJars.targetAppJars.size());
        System.out.println("Dependency App Jars: " + loadedJars.depAppJars.size());
        System.out.println("Lib Jars: " + loadedJars.libJars.size());
        System.out.println("------------------------------------------");

        // 3. Phase 2: Asset Discovery
        String projectName = new File(targetPath).getName();
        File apiFile = new File(workspaceDir, "api.txt");
        
        // Force scan if filter is provided OR api.txt is missing
        // If mode is API, we always run discovery (unless explicitly cached? No, explicit mode usually implies execution)
        // Actually, if user runs -m api, they likely want to see the output, so we should run it.
        // But if they run -m scan, we only run discovery if needed.
        
        boolean isApiMode = "api".equalsIgnoreCase(mode);
        boolean isScanMode = "scan".equalsIgnoreCase(mode);
        
        if (!isApiMode && !isScanMode) {
            System.err.println("Invalid mode: " + mode + ". Use 'api' or 'scan'.");
            return 1;
        }

        boolean forceDiscovery = (filterAnnotations != null && !filterAnnotations.isEmpty()) || isApiMode;
        
        if (!apiFile.exists() || forceDiscovery) {
            com.jbytescanner.engine.DiscoveryEngine discoveryEngine = 
                    new com.jbytescanner.engine.DiscoveryEngine(loadedJars.targetAppJars, loadedJars.depAppJars, loadedJars.libJars, workspaceDir, filterAnnotations);
            discoveryEngine.run();
            System.out.println("Phase 2 Complete. API list generated for project: " + projectName);
        } else {
            System.out.println("Phase 2 Skipped. Using existing api.txt for project: " + projectName);
        }

        // Phase 2.5: Secret Scanner (Execute in BOTH api and scan modes)
        // Ensure Soot is initialized if Discovery was skipped (e.g. in 'scan' mode with existing api.txt)
        // Note: In 'api' mode, DiscoveryEngine.run() already initializes Soot.
        if (isScanMode && apiFile.exists() && !forceDiscovery) {
             List<String> combinedLibs = new java.util.ArrayList<>(loadedJars.libJars);
             if (loadedJars.depAppJars != null) combinedLibs.addAll(loadedJars.depAppJars);
             com.jbytescanner.core.SootManager.initSoot(loadedJars.targetAppJars, combinedLibs, false);
        }

        System.out.println("------------------------------------------");
        System.out.println("Starting Secret Scanner...");
        com.jbytescanner.secret.SecretScanner secretScanner = new com.jbytescanner.secret.SecretScanner();
        List<com.jbytescanner.secret.SecretFinding> findings = secretScanner.scan(loadedJars.targetAppJars);
        secretScanner.writeReport(workspaceDir, findings);
        System.out.println("Secret Scan Complete. Findings: " + findings.size());
        
        // Phase 9.2: Gadget Inspector
        System.out.println("------------------------------------------");
        System.out.println("Starting Gadget Inspector (Phase 9.2)...");
        com.jbytescanner.engine.GadgetInspector gadgetInspector = new com.jbytescanner.engine.GadgetInspector();
        List<com.jbytescanner.model.Gadget> gadgets = gadgetInspector.inspect(loadedJars.libJars);
        
        System.out.println("Found " + gadgets.size() + " usable gadgets based on dependencies.");
        if (!gadgets.isEmpty()) {
            File gadgetFile = new File(workspaceDir, "gadgets.txt");
            try (java.io.PrintWriter pw = new java.io.PrintWriter(gadgetFile, "UTF-8")) {
                pw.println("### Potential Gadgets (Grouped by Dependencies) ###");
                
                // Grouping Logic
                java.util.Map<String, java.util.List<com.jbytescanner.model.Gadget>> grouped = new java.util.HashMap<>();
                
                for (com.jbytescanner.model.Gadget g : gadgets) {
                    String key = "No Dependencies (JDK/Universal)";
                    if (g.getDependencies() != null && !g.getDependencies().isEmpty()) {
                        key = g.getDependencies().stream()
                             .map(d -> {
                                 if (d.getArtifact() != null) return d.getArtifact();
                                 if (d.getRaw() != null) return d.getRaw();
                                 return "unknown";
                             })
                             .sorted()
                             .collect(java.util.stream.Collectors.joining(", "));
                    }
                    grouped.computeIfAbsent(key, k -> new java.util.ArrayList<>()).add(g);
                }
                
                // Output
                for (java.util.Map.Entry<String, java.util.List<com.jbytescanner.model.Gadget>> entry : grouped.entrySet()) {
                    pw.println("==================================================");
                    pw.println("Dependency Set: [" + entry.getKey() + "]");
                    pw.println("--------------------------------------------------");
                    for (com.jbytescanner.model.Gadget g : entry.getValue()) {
                        pw.println("* " + g.getName() + " (" + g.getClassName() + ")");
                        if (g.getDescription() != null && !g.getDescription().isEmpty()) {
                            pw.println("  Desc: " + g.getDescription().replace("\n", " "));
                        }
                    }
                    pw.println();
                }

            } catch (Exception e) {
                logger.error("Failed to write gadget report", e);
            }
            System.out.println("Gadget report written to: " + gadgetFile.getAbsolutePath());
        }

        if (isApiMode) {
            System.out.println("Mode 'api' finished. Exiting.");
            return 0;
        }
        
        System.out.println("------------------------------------------");
        
        // 4. Phase 3: Taint Analysis
        com.jbytescanner.engine.TaintEngine taintEngine = 
                new com.jbytescanner.engine.TaintEngine(loadedJars.targetAppJars, loadedJars.depAppJars, loadedJars.libJars, workspaceDir, configManager);
        taintEngine.run();
        
        System.out.println("Phase 3 Complete. Analysis finished.");
        
        return 0;
    }
}
