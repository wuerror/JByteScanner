package com.jbytescanner.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pascal.taie.Main;
import pascal.taie.World;

import java.util.ArrayList;
import java.util.List;

public class TaieManager {
    private static final Logger logger = LoggerFactory.getLogger(TaieManager.class);

    /**
     * Initialize Tai-e World context.
     *
     * @param targetAppJars The application jars (business logic).
     * @param libJars       The dependency/library jars.
     * @param isTaint       Whether we are running taint analysis (true) or just discovery (false).
     */
    public static void initTaie(List<String> targetAppJars, List<String> libJars,
                                boolean isTaint, java.io.File outputDir) {
        logger.info("Initializing Tai-e Engine...");

        List<String> args = new ArrayList<>();

        // 1. App Class Path: only business logic classes
        // PERFORMANCE OPTIMIZATION 1: No --input-classes all
        // Tai-e defaults to treating app-class-path classes as application classes.
        if (targetAppJars != null && !targetAppJars.isEmpty()) {
            args.add("--app-class-path");
            args.add(String.join(System.getProperty("path.separator"), targetAppJars));
        }

        // 2. Class Path: library and dependency jars
        if (libJars != null && !libJars.isEmpty()) {
            args.add("--class-path");
            args.add(String.join(System.getProperty("path.separator"), libJars));
        }

        // -pp: ALWAYS required when Tai-e is embedded as a library.
        // Without it, Tai-e looks for 'java-benchmarks/JREs/' git submodule which doesn't
        // exist in the packaged fat jar. With -pp, Soot uses the running JVM's classpath.
        args.add("-pp");

        // -ap: Allow phantom classes (referenced but not on classpath).
        // Soot's closed-world assumption would fail on incomplete classpaths (e.g. slf4j,
        // spring-web referenced by app classes but not included in libJars).
        // This is one of Tai-e's core advantages over raw Soot.
        args.add("-ap");

        // Direct Tai-e output (options.yml, plan files, etc.) to the workspace dir
        // to keep them co-located with JByteScanner results and away from the source tree.
        if (outputDir != null) {
            args.add("--output-dir");
            args.add(outputDir.getAbsolutePath());
        }

        // No -a argument: Tai-e will build with an empty analysis plan.
        // This is sufficient for discovery mode — World is fully built but no analyses run.
        String[] argsArray = args.toArray(new String[0]);
        logger.debug("Tai-e initialization args: {}", String.join(" ", argsArray));

        // Main.buildWorld handles Options parsing, logging setup, and WorldBuilder execution.
        Main.buildWorld(argsArray);

        logger.info("Tai-e Engine Initialized. Application classes: {}",
            World.get().getClassHierarchy().applicationClasses().count());
    }
}
