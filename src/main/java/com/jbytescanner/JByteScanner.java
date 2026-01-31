package com.jbytescanner;

import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.core.JarLoader;
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

    @Parameters(index = "0", description = "Target directory or JAR file to scan")
    private String targetPath;

    @Option(names = {"-c", "--config"}, description = "Path to custom configuration file (optional)")
    private String configPath;

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
        JarLoader.LoadedJars loadedJars = jarLoader.loadJars(targetPath, scanPackages);
        
        System.out.println("------------------------------------------");
        System.out.println("Target: " + targetPath);
        System.out.println("Workspace: " + workspaceDir.getAbsolutePath());
        System.out.println("App Jars: " + loadedJars.appJars.size());
        System.out.println("Lib Jars: " + loadedJars.libJars.size());
        System.out.println("------------------------------------------");

        // 3. Phase 2: Asset Discovery
        String projectName = new File(targetPath).getName();
        File apiFile = new File(workspaceDir, "api.txt");
        if (!apiFile.exists()) {
            com.jbytescanner.engine.DiscoveryEngine discoveryEngine = 
                    new com.jbytescanner.engine.DiscoveryEngine(loadedJars.appJars, loadedJars.libJars, workspaceDir);
            discoveryEngine.run();
            System.out.println("Phase 2 Complete. API list generated for project: " + projectName);
        } else {
            System.out.println("Phase 2 Skipped. Using existing api.txt for project: " + projectName);
        }
        
        System.out.println("------------------------------------------");
        
        // 4. Phase 3: Taint Analysis
        com.jbytescanner.engine.TaintEngine taintEngine = 
                new com.jbytescanner.engine.TaintEngine(loadedJars.appJars, loadedJars.libJars, workspaceDir, configManager);
        taintEngine.run();
        
        System.out.println("Phase 3 Complete. Analysis finished.");
        
        return 0;
    }
}
