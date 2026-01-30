package com.jbytescanner;

import com.jbytescanner.config.ConfigManager;
import com.jbytescanner.core.JarLoader;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.util.List;
import java.util.concurrent.Callable;

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

        // 1. Initialize Configuration
        ConfigManager configManager = new ConfigManager();
        // TODO: Support custom config path in ConfigManager if needed, for now it looks in CWD
        configManager.init();
        
        System.out.println("Loaded Sources: " + configManager.getConfig().getSources().size());
        System.out.println("Loaded Sinks: " + configManager.getConfig().getSinks().size());

        // 2. Load JARs
        JarLoader jarLoader = new JarLoader();
        List<String> jars = jarLoader.loadJars(targetPath);
        
        System.out.println("------------------------------------------");
        System.out.println("Target: " + targetPath);
        System.out.println("Found Archives:");
        for (String jar : jars) {
            System.out.println(" - " + jar);
        }
        System.out.println("------------------------------------------");

        // 3. Phase 2: Asset Discovery
        String projectName = new File(targetPath).getName();
        com.jbytescanner.engine.DiscoveryEngine discoveryEngine = 
                new com.jbytescanner.engine.DiscoveryEngine(jars, projectName);
        discoveryEngine.run();

        System.out.println("Phase 2 Complete. API list generated for project: " + projectName);
        
        return 0;
    }
}
