package com.jbytescanner.graph;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.PackManager;
import soot.Scene;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.options.Options;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

public class CallGraphBuilder {
    private static final Logger logger = LoggerFactory.getLogger(CallGraphBuilder.class);

    public CallGraph build() {
        logger.info("Configuring Call Graph Builder (CHA)...");

        // Force CHA (Class Hierarchy Analysis)
        // Explicitly disable SPARK to save memory/time for Phase 3 start
        Options.v().setPhaseOption("cg.spark", "enabled:false");
        Options.v().setPhaseOption("cg.cha", "enabled:true");
        
        // Exclude library packages from analysis to speed up WPO
        configureExclusions();

        logger.info("Running Soot Packs (wjtp)... This may take a while.");
        PackManager.v().runPacks();
        
        return Scene.v().getCallGraph();
    }

    private void configureExclusions() {
        // Exclude standard libraries and common frameworks
        List<String> excludeList = new ArrayList<>();
        excludeList.add("java.");
        excludeList.add("javax.");
        excludeList.add("sun.");
        excludeList.add("jdk.");
        excludeList.add("org.slf4j.");
        excludeList.add("org.apache.commons.logging.");
        
        // Convert to Options format if necessary or use Scene.v().addBasicClass for phantom
        // Soot has -exclude option.
        // Since we already loaded Scene in SootManager, we rely on Options set there OR set them here if not too late.
        // Actually, exclude options should be set BEFORE loadNecessaryClasses. 
        // We will need to move exclusion logic to SootManager in the next refactor.
        // For now, PackManager run will use whatever was loaded.
    }
}
