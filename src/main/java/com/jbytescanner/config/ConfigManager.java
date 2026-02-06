package com.jbytescanner.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

public class ConfigManager {
    private static final Logger logger = LoggerFactory.getLogger(ConfigManager.class);
    private static final String CONFIG_FILENAME = "rules.yaml";
    private static final String DEFAULT_CONFIG_RESOURCE = "/default_rules.yaml";

    private Config config;

    private File configFile; // Keep track of the file location

    /**
     * Init config from a specific workspace directory (e.g., target/.jbytescanner/)
     */
    public void init(File workspaceDir) {
        if (!workspaceDir.exists()) {
            workspaceDir.mkdirs();
        }

        this.configFile = new File(workspaceDir, CONFIG_FILENAME);
        
        // Strategy: 
        // 1. Look in workspace/.jbytescanner/rules.yaml (Project specific)
        // 2. If not found, create it from default template
        
        if (!configFile.exists()) {
            logger.info("Project-specific rules not found. Creating default at: {}", configFile.getAbsolutePath());
            extractDefaultConfig(configFile);
        } else {
            logger.info("Loaded project-specific configuration: {}", configFile.getAbsolutePath());
        }
        
        loadConfig(configFile);
    }

    public void updateScanPackage(String packageName) {
        if (config == null || packageName == null) return;
        
        // Update in-memory
        if (config.getScanConfig() == null) {
            config.setScanConfig(new ScanConfig());
        }
        
        // If list is empty or doesn't contain the package
        if (config.getScanConfig().getScanPackages().isEmpty()) {
            config.getScanConfig().getScanPackages().add(packageName);
            logger.info("Auto-configured scan_package: {}", packageName);
            
            // Persist to file
            saveConfig();
        }
    }

    private void saveConfig() {
        if (configFile == null) return;
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        try {
            mapper.writeValue(configFile, config);
            logger.info("Updated configuration saved to: {}", configFile.getAbsolutePath());
        } catch (IOException e) {
            logger.error("Failed to save updated configuration", e);
        }
    }

    private void extractDefaultConfig(File destination) {
        try (InputStream in = getClass().getResourceAsStream(DEFAULT_CONFIG_RESOURCE)) {
            if (in == null) {
                logger.error("Could not find default configuration in resources: {}", DEFAULT_CONFIG_RESOURCE);
                return;
            }
            Files.copy(in, destination.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            logger.error("Failed to extract default configuration", e);
        }
    }

    private void loadConfig(File configFile) {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        try {
            this.config = mapper.readValue(configFile, Config.class);
            // Default AuthConfig if null
            if (config.getScanConfig().getAuthConfig() == null) {
                config.getScanConfig().setAuthConfig(new AuthConfig());
            }
            logger.info("Configuration loaded. Sources: {}, Sinks: {}", 
                    config.getSources().size(), config.getSinks().size());
        } catch (IOException e) {
            logger.error("Failed to parse configuration file", e);
            throw new RuntimeException("Configuration load failed", e);
        }
    }

    public Config getConfig() {
        return config;
    }
}
