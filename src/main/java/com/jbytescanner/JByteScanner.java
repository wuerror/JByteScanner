package com.jbytescanner;

import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.core.ClasspathPlanner;
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
        description = "Java Bytecode Security Scanner based on Tai-e")
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

    @Option(names = {"--worker"}, description = "Run Tai-e analysis in an isolated worker JVM (default: true)", negatable = true, defaultValue = "true")
    private boolean worker = true;

    @Option(names = {"--max-heap-mb"}, description = "Worker JVM -Xmx in megabytes (default: 8192)")
    private Integer maxHeapMb;

    @Option(names = {"--timeout-minutes"}, description = "Worker wall-clock timeout in minutes; 0 disables (default: 0)")
    private Integer timeoutMinutes;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new JByteScanner()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        System.out.println("==========================================");
        System.out.println("   JByteScanner - Next Gen Static Analysis");
        System.out.println("==========================================");

        // Memory check: host heap only matters for discovery/secret; Tai-e uses worker budget.
        if ("scan".equalsIgnoreCase(mode) && !worker) {
            long maxHeapMB = Runtime.getRuntime().maxMemory() / (1024 * 1024);
            if (maxHeapMB < 4096) {
                System.out.println("[WARN] In-process mode: max heap is only " + maxHeapMB + " MB. Large projects may OOM.");
                System.out.println("[WARN] Prefer default worker mode, or: java -Xmx8g -jar JByteScanner.jar --no-worker ...");
            }
        }

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
        applyResourceBudgetOverrides(configManager);

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

        // P0.2: classpath preflight, SHA/version mediation, mixed-JAR package scope.
        ClasspathPlanner.PlanResult classpathPlan =
                new ClasspathPlanner().plan(loadedJars, scanPackages, workspaceDir);
        loadedJars = classpathPlan.jars;
        
        System.out.println("------------------------------------------");
        System.out.println("Target: " + targetPath);
        System.out.println("Workspace: " + workspaceDir.getAbsolutePath());
        System.out.println("Target App Jars (Analysis Scope): " + loadedJars.targetAppJars.size());
        System.out.println("Dependency App Jars: " + loadedJars.depAppJars.size());
        System.out.println("Lib Jars: " + loadedJars.libJars.size());
        if (classpathPlan.report != null) {
            System.out.println("Classpath preflight: droppedDup=" + classpathPlan.report.droppedDuplicateCount
                    + ", mixedExtract=" + classpathPlan.report.mixedJarExtractions
                    + ", warnings=" + classpathPlan.report.warnings.size());
        }
        System.out.println("------------------------------------------");

        // 3. Phase 2: Asset Discovery
        String projectName = new File(targetPath).getName();
        File apiFile = new File(workspaceDir, "api.txt");
        
        boolean isApiMode = "api".equalsIgnoreCase(mode);
        boolean isScanMode = "scan".equalsIgnoreCase(mode);
        
        if (!isApiMode && !isScanMode) {
            System.err.println("Invalid mode: " + mode + ". Use 'api' or 'scan'.");
            return 1;
        }

        // Design: api.txt acts as a human-editable source whitelist.
        // Once it exists, we assume the user has curated it — we will NOT
        // auto-overwrite it even if the classpath changes.
        // - missing api.txt → always discover
        // - -m api              → always rediscover
        // - --filter-annotation → always rediscover
        // - api.txt exists      → skip discovery, respect manual edits
        boolean forceDiscovery = (filterAnnotations != null && !filterAnnotations.isEmpty()) || isApiMode;
        boolean cacheStale = com.jbytescanner.engine.DiscoveryEngine.isApiCacheStale(
                workspaceDir, loadedJars.targetAppJars);

        if (!apiFile.exists() || forceDiscovery) {
            com.jbytescanner.engine.DiscoveryEngine discoveryEngine =
                    new com.jbytescanner.engine.DiscoveryEngine(loadedJars.targetAppJars, loadedJars.depAppJars, loadedJars.libJars, workspaceDir, filterAnnotations);
            discoveryEngine.run();
            System.out.println("Phase 2 Complete. API list generated for project: " + projectName);
        } else {
            if (cacheStale) {
                System.out.println("Phase 2: api.txt exists but classpath has changed. Using existing api.txt as-is.");
                System.out.println("         Run with -m api to regenerate the full route list.");
            } else {
                System.out.println("Phase 2 Skipped. Using existing api.txt for project: " + projectName);
            }
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

    private void applyResourceBudgetOverrides(ConfigManager configManager) {
        com.jbytescanner.config.ScanConfig scanConfig = configManager.getConfig().getScanConfig();
        if (scanConfig == null) {
            return;
        }
        com.jbytescanner.config.ResourceBudget budget = scanConfig.getResourceBudget();
        budget.setWorkerEnabled(worker);
        if (maxHeapMb != null && maxHeapMb > 0) {
            budget.setMaxHeapMb(maxHeapMb);
        }
        if (timeoutMinutes != null && timeoutMinutes >= 0) {
            budget.setTimeoutMinutes(timeoutMinutes);
        }
        System.out.println("Resource budget: worker=" + budget.isWorkerEnabled()
                + ", maxHeapMb=" + budget.getMaxHeapMb()
                + ", timeoutMinutes=" + budget.getTimeoutMinutes());
    }
}
