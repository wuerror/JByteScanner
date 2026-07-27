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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class ConfigManager {
    private static final Logger logger = LoggerFactory.getLogger(ConfigManager.class);
    private static final String CONFIG_FILENAME = "rules.yaml";
    private static final String DEFAULT_CONFIG_RESOURCE = "/default_rules.yaml";
    private static final int CURRENT_RULES_VERSION = 4;

    private Config config;
    private File configFile;

    /**
     * Init config from a specific workspace directory (e.g., target/.jbytescanner/).
     */
    public void init(File workspaceDir) {
        if (!workspaceDir.exists() && !workspaceDir.mkdirs()) {
            throw new IllegalStateException("Could not create workspace directory: " + workspaceDir);
        }

        this.configFile = new File(workspaceDir, CONFIG_FILENAME);

        // Project-specific rules remain authoritative. A newly introduced bundled rule
        // is merged only when the file's rules_version is older than this release.
        if (!configFile.exists()) {
            logger.info("Project-specific rules not found. Creating default at: {}",
                    configFile.getAbsolutePath());
            extractDefaultConfig(configFile);
        } else {
            logger.info("Loaded project-specific configuration: {}", configFile.getAbsolutePath());
        }

        loadConfig(configFile);
    }

    public void updateScanPackage(String packageName) {
        if (config == null || packageName == null) return;

        if (config.getScanConfig() == null) {
            config.setScanConfig(new ScanConfig());
        }

        if (config.getScanConfig().getScanPackages().isEmpty()) {
            config.getScanConfig().getScanPackages().add(packageName);
            logger.info("Auto-configured scan_package: {}", packageName);
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
                throw new IllegalStateException(
                        "Could not find default configuration in resources: " + DEFAULT_CONFIG_RESOURCE);
            }
            Files.copy(in, destination.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new RuntimeException("Failed to extract default configuration", e);
        }
    }

    private void loadConfig(File configFile) {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        try {
            Config loaded = mapper.readValue(configFile, Config.class);
            normalize(loaded);

            if (loaded.getRulesVersion() < CURRENT_RULES_VERSION) {
                int oldVersion = loaded.getRulesVersion();
                Config bundledDefaults = loadBundledDefaults(mapper);
                MigrationStats stats = mergeBundledDefaults(loaded, bundledDefaults);
                loaded.setRulesVersion(CURRENT_RULES_VERSION);
                this.config = loaded;

                backupLegacyConfig(configFile, oldVersion);
                saveConfig();
                logger.info(
                        "Migrated rules.yaml from version {} to {}: added {} source(s), "
                                + "{} sink(s), {} transfer(s), enriched {} existing rule(s).",
                        oldVersion, CURRENT_RULES_VERSION, stats.sourcesAdded(), stats.sinksAdded(),
                        stats.transfersAdded(), stats.rulesEnriched());
            } else {
                this.config = loaded;
            }

            logger.info("Configuration loaded. Sources: {}, Sinks: {}, Transfers: {}",
                    config.getSources().size(), config.getSinks().size(), config.getTransfers().size());
        } catch (IOException e) {
            logger.error("Failed to parse configuration file", e);
            throw new RuntimeException("Configuration load failed", e);
        }
    }

    private Config loadBundledDefaults(ObjectMapper mapper) throws IOException {
        try (InputStream in = getClass().getResourceAsStream(DEFAULT_CONFIG_RESOURCE)) {
            if (in == null) {
                throw new IOException("Bundled default rules not found: " + DEFAULT_CONFIG_RESOURCE);
            }
            Config defaults = mapper.readValue(in, Config.class);
            normalize(defaults);
            return defaults;
        }
    }

    private void backupLegacyConfig(File source, int oldVersion) throws IOException {
        File backup = new File(source.getParentFile(),
                CONFIG_FILENAME + ".bak-v" + Math.max(oldVersion, 0));
        if (!backup.exists()) {
            Files.copy(source.toPath(), backup.toPath());
            logger.info("Backed up pre-migration rules to: {}", backup.getAbsolutePath());
        }
    }

    private static void normalize(Config value) {
        if (value.getScanConfig() == null) value.setScanConfig(new ScanConfig());
        if (value.getScanConfig().getAuthConfig() == null) {
            value.getScanConfig().setAuthConfig(new AuthConfig());
        }
        if (value.getSources() == null) value.setSources(new ArrayList<>());
        if (value.getSinks() == null) value.setSinks(new ArrayList<>());
        if (value.getTransfers() == null) value.setTransfers(new ArrayList<>());
    }

    /**
     * Merges newly bundled rules without replacing project-specific settings.
     * Existing rules win; only fields that were absent in an old rule are enriched.
     */
    static MigrationStats mergeBundledDefaults(Config target, Config defaults) {
        normalize(target);
        normalize(defaults);
        int sourcesAdded = 0;
        int sinksAdded = 0;
        int transfersAdded = 0;
        int rulesEnriched = 0;

        for (SourceRule bundled : defaults.getSources()) {
            SourceRule existing = findSource(target.getSources(), bundled);
            if (existing == null) {
                target.getSources().add(bundled);
                sourcesAdded++;
            } else {
                boolean changed = false;
                if (existing.getType() == null && bundled.getType() != null) {
                    existing.setType(bundled.getType());
                    changed = true;
                }
                if (existing.getIndex() == null && bundled.getIndex() != null) {
                    existing.setIndex(bundled.getIndex());
                    changed = true;
                }
                if (existing.getTaintType() == null && bundled.getTaintType() != null) {
                    existing.setTaintType(bundled.getTaintType());
                    changed = true;
                }
                if (changed) rulesEnriched++;
            }
        }

        for (SinkRule bundled : defaults.getSinks()) {
            SinkRule existing = findSink(target.getSinks(), bundled.getSignature());
            if (existing == null) {
                target.getSinks().add(bundled);
                sinksAdded++;
            } else {
                boolean changed = false;
                if (existing.getType() == null && bundled.getType() != null) {
                    existing.setType(bundled.getType());
                    changed = true;
                }
                if (existing.getVulnType() == null && bundled.getVulnType() != null) {
                    existing.setVulnType(bundled.getVulnType());
                    changed = true;
                }
                if (existing.getCategory() == null && bundled.getCategory() != null) {
                    existing.setCategory(bundled.getCategory());
                    changed = true;
                }
                if (existing.getSeverity() == null && bundled.getSeverity() != null) {
                    existing.setSeverity(bundled.getSeverity());
                    changed = true;
                }
                if (existing.getIndex() == null && bundled.getIndex() != null) {
                    existing.setIndex(bundled.getIndex());
                    changed = true;
                }
                if (changed) rulesEnriched++;
            }
        }

        for (TransferRule bundled : defaults.getTransfers()) {
            TransferRule existing = findTransfer(target.getTransfers(), bundled);
            if (existing == null) {
                target.getTransfers().add(bundled);
                transfersAdded++;
            } else if (existing.getType() == null && bundled.getType() != null) {
                existing.setType(bundled.getType());
                rulesEnriched++;
            }
        }

        return new MigrationStats(sourcesAdded, sinksAdded, transfersAdded, rulesEnriched);
    }

    private static SourceRule findSource(List<SourceRule> rules, SourceRule wanted) {
        for (SourceRule rule : rules) {
            if (Objects.equals(rule.getSignature(), wanted.getSignature())
                    && Objects.equals(rule.getValue(), wanted.getValue())) {
                return rule;
            }
        }
        return null;
    }

    private static SinkRule findSink(List<SinkRule> rules, String signature) {
        for (SinkRule rule : rules) {
            if (Objects.equals(rule.getSignature(), signature)) return rule;
        }
        return null;
    }

    private static TransferRule findTransfer(List<TransferRule> rules, TransferRule wanted) {
        for (TransferRule rule : rules) {
            if (Objects.equals(rule.getMethod(), wanted.getMethod())
                    && Objects.equals(rule.getFrom(), wanted.getFrom())
                    && Objects.equals(rule.getTo(), wanted.getTo())) {
                return rule;
            }
        }
        return null;
    }

    record MigrationStats(int sourcesAdded, int sinksAdded,
                          int transfersAdded, int rulesEnriched) {
    }

    public Config getConfig() {
        return config;
    }
}
