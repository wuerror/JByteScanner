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
        
        // Exclusions are now handled globally in SootManager.initSoot

        logger.info("Running Soot Packs (wjtp)... This may take a while.");
        PackManager.v().runPacks();
        
        return Scene.v().getCallGraph();
    }
}
