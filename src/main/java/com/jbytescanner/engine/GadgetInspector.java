package com.jbytescanner.engine;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jbytescanner.model.Component;
import com.jbytescanner.model.Gadget;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.stream.Collectors;

public class GadgetInspector {
    private static final Logger logger = LoggerFactory.getLogger(GadgetInspector.class);
    private List<Gadget> knownGadgets;
    private final ScaScanner scaScanner = new ScaScanner();

    public GadgetInspector() {
        loadGadgets();
    }

    private void loadGadgets() {
        try (InputStream is = getClass().getResourceAsStream("/gadgets.json")) {
            if (is == null) {
                logger.warn("gadgets.json not found in classpath. Gadget Suggestion will be disabled.");
                knownGadgets = Collections.emptyList();
                return;
            }
            ObjectMapper mapper = new ObjectMapper();
            knownGadgets = mapper.readValue(is, new TypeReference<List<Gadget>>() {});
            logger.info("Loaded {} gadget definitions.", knownGadgets.size());
        } catch (IOException e) {
            logger.error("Failed to load gadgets.json", e);
            knownGadgets = Collections.emptyList();
        }
    }

    public List<Gadget> inspect(List<String> libJars) {
        if (knownGadgets.isEmpty()) return Collections.emptyList();

        // 1. SCA Scan
        List<Component> components = scaScanner.scan(libJars);
        
        // 2. Match
        List<Gadget> matchedGadgets = new ArrayList<>();
        
        for (Gadget gadget : knownGadgets) {
            if (isGadgetApplicable(gadget, components)) {
                matchedGadgets.add(gadget);
            }
        }
        
        logger.info("Gadget Inspector found {} potential gadgets.", matchedGadgets.size());
        return matchedGadgets;
    }

    private boolean isGadgetApplicable(Gadget gadget, List<Component> components) {
        if (gadget.getDependencies() == null || gadget.getDependencies().isEmpty()) {
            return false; // No deps usually means JDK only or abstract, skip for safety or include?
            // Actually, JDK-only gadgets (e.g. RMI) are always applicable if JDK version matches.
            // But we don't scan JDK version here. Let's assume JDK-only are valid for now?
            // No, let's be conservative. If no deps listed, maybe it's abstract.
        }

        for (Gadget.Dependency dep : gadget.getDependencies()) {
            boolean found = false;
            
            // Check if ANY component matches this dependency rule
            for (Component comp : components) {
                if (matches(dep, comp)) {
                    found = true;
                    break;
                }
            }
            
            // If a required dependency is missing, gadget is not applicable
            if (!found) return false;
        }
        
        return true;
    }

    private boolean matches(Gadget.Dependency dep, Component comp) {
        // 1. Group ID Check (if present in rule)
        if (dep.getGroup() != null && !dep.getGroup().isEmpty()) {
            if (comp.getGroupId() != null && !comp.getGroupId().equals(dep.getGroup())) {
                return false;
            }
        }

        // 2. Artifact ID Check (Fuzzy or Exact)
        String targetArtifact = dep.getArtifact();
        if (targetArtifact == null && dep.getRaw() != null) {
             targetArtifact = dep.getRaw(); // Fallback to raw string
        }
        
        if (targetArtifact != null) {
            String compArtifact = comp.getArtifactId();
            if (compArtifact == null) compArtifact = comp.getSourcePath(); // Fallback to filename
            
            // Loose matching: "commons-collections" matches "commons-collections-3.2.1.jar"
            if (!compArtifact.contains(targetArtifact)) {
                return false;
            }
        }

        // 3. Version Check
        // Very simple check: if rule has version, check if component version contains it
        // TODO: Implement semantic version range check (e.g. < 3.2.1)
        if (dep.getVersion() != null && !dep.getVersion().equals("*")) {
            String ruleVer = dep.getVersion();
            String compVer = comp.getVersion();
            
            if (compVer == null) return true; // Can't verify, assume match (False Positive > False Negative)
            
            // Exact match
            if (compVer.equals(ruleVer)) return true;
            
            // Prefix match
            if (compVer.startsWith(ruleVer)) return true;
            
            // Range check is hard without a library. 
            // For now, if rule contains "<" or ">", we ignore version check to avoid False Negatives.
            if (ruleVer.contains("<") || ruleVer.contains(">") || ruleVer.contains("~")) {
                return true; 
            }
            
            return false;
        }

        return true;
    }
}
