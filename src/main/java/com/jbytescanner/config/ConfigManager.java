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

    /**
     * Init config from a specific workspace directory (e.g., target/.jbytescanner/)
     */
    public void init(File workspaceDir) {
        if (!workspaceDir.exists()) {
            workspaceDir.mkdirs();
        }

        File configFile = new File(workspaceDir, CONFIG_FILENAME);
        
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
