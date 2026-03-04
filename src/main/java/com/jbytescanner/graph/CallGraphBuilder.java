package com.jbytescanner.graph;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.options.Options;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CallGraphBuilder {
    private static final Logger logger = LoggerFactory.getLogger(CallGraphBuilder.class);
    private static final int MAX_DANGLING_RESOLUTION = 25;
    private static final Pattern DANGLING_PATTERN =
            Pattern.compile("but\\s+([\\w.$/]+)\\s+is at resolving level DANGLING");

    public CallGraph build() {
        logger.info("Configuring Call Graph Builder (CHA)...");

        // Force CHA (Class Hierarchy Analysis)
        // Explicitly disable SPARK to save memory/time for Phase 3 start
        Options.v().setPhaseOption("cg.spark", "enabled:false");
        Options.v().setPhaseOption("cg.cha", "enabled:true");
        
        // Exclusions are now handled globally in SootManager.initSoot

        logger.info("Running Soot Packs (wjtp)... This may take a while.");
        runPacksWithDanglingRecovery();

        return Scene.v().getCallGraph();
    }

    private void runPacksWithDanglingRecovery() {
        Set<String> resolved = new LinkedHashSet<>();
        while (true) {
            try {
                PackManager.v().runPacks();
                if (!resolved.isEmpty()) {
                    logger.info("Soot packs succeeded after auto-resolving {} missing dependencies: {}",
                            resolved.size(), resolved);
                }
                return;
            } catch (RuntimeException ex) {
                String danglingClass = extractDanglingClass(ex);
                if (danglingClass == null) {
                    throw ex;
                }

                if (resolved.size() >= MAX_DANGLING_RESOLUTION) {
                    logger.error("Reached max dangling resolution attempts ({}). Last unresolved class: {}",
                            MAX_DANGLING_RESOLUTION, danglingClass);
                    throw ex;
                }

                if (resolved.contains(danglingClass)) {
                    logger.error("Dangling class {} already resolved but exception persists.", danglingClass);
                    throw ex;
                }

                resolved.add(danglingClass);
                logger.warn("Detected dangling dependency '{}'. Forcing hierarchy resolution (attempt {}/{}).",
                        danglingClass, resolved.size(), MAX_DANGLING_RESOLUTION);

                try {
                    SootClass forced = Scene.v().forceResolve(danglingClass, SootClass.HIERARCHY);
                    if (forced == null) {
                        logger.warn("forceResolve returned null for {}", danglingClass);
                    } else if (forced.isPhantom()) {
                        logger.debug("Class {} resolved as phantom.", danglingClass);
                    }
                } catch (RuntimeException resolveEx) {
                    logger.error("Failed to force resolve {}: {}", danglingClass, resolveEx.toString());
                    throw resolveEx;
                }
            }
        }
    }

    private String extractDanglingClass(Throwable throwable) {
        while (throwable != null) {
            String message = throwable.getMessage();
            if (message != null) {
                Matcher matcher = DANGLING_PATTERN.matcher(message);
                if (matcher.find()) {
                    return matcher.group(1).replace('/', '.').trim();
                }
            }
            throwable = throwable.getCause();
        }
        return null;
    }
}
