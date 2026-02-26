package com.jbytescanner.engine;

import com.jbytescanner.config.ConfigManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.List;

public class TaintEngine {
    private static final Logger logger = LoggerFactory.getLogger(TaintEngine.class);

    private final List<String> targetAppJars;
    private final List<String> depAppJars;
    private final List<String> libJars;
    private final File workspaceDir;
    private final ConfigManager configManager;

    public TaintEngine(List<String> targetAppJars, List<String> depAppJars, List<String> libJars, File workspaceDir, ConfigManager configManager) {
        this.targetAppJars = targetAppJars;
        this.depAppJars = depAppJars;
        this.libJars = libJars;
        this.workspaceDir = workspaceDir;
        this.configManager = configManager;
    }

    public void run() {
        logger.info("Tai-e Taint Engine will be implemented in Step 5...");
    }
}
