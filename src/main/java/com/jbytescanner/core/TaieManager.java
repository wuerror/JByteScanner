package com.jbytescanner.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pascal.taie.Main;
import pascal.taie.config.AnalysisConfig;
import pascal.taie.config.ConfigManager;
import pascal.taie.config.Options;
import pascal.taie.World;
import pascal.taie.frontend.Compiler;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class TaieManager {
    private static final Logger logger = LoggerFactory.getLogger(TaieManager.class);

    /**
     * Initialize Tai-e World context.
     *
     * @param targetAppJars The application jars (business logic).
     * @param libJars       The dependency/library jars.
     * @param isTaint       Whether we are running taint analysis (true) or just discovery (false).
     */
    public static void initTaie(List<String> targetAppJars, List<String> libJars, boolean isTaint) {
        logger.info("Initializing Tai-e Engine...");

        List<String> args = new ArrayList<>();

        // 1. App Class Path (--app-class-path)
        // Only target jars should be here, otherwise we get thousands of classes
        if (targetAppJars != null && !targetAppJars.isEmpty()) {
            args.add("--app-class-path");
            args.add(String.join(System.getProperty("path.separator"), targetAppJars));
        }

        // 2. Class Path (--class-path)
        // Library and dependency jars go here
        if (libJars != null && !libJars.isEmpty()) {
            args.add("--class-path");
            args.add(String.join(System.getProperty("path.separator"), libJars));
        }

        // PERFORMANCE OPTIMIZATION 1: No --input-classes all
        // Tai-e defaults to app-class-path as the application classes.

        // PERFORMANCE OPTIMIZATION 2: Careful use of -pp
        // For taint analysis, we usually need the JDK classes.
        // For pure API discovery, we might get away without them or just basic classes.
        // Let's add -pp for taint, or just add it anyway if required by some IR loading,
        // but avoid loading IR for them!
        if (isTaint) {
            args.add("-pp"); // Prepend JDK rt.jar
        }

        // We don't want to run any default analyses right now if we are just setting up the World.
        // If we are just doing discovery, we just need World initialized.
        args.add("-a");
        args.add("only-allow-empty-analyses=true");

        // Convert to array
        String[] argsArray = args.toArray(new String[0]);
        logger.debug("Tai-e initialization args: {}", String.join(" ", argsArray));

        // Start Tai-e
        // Tai-e sets up World during Option parsing and execution setup.
        Options.parse(argsArray);
        World.reset();
        World.get().setOptions(Options.get());
        
        // This triggers the frontend (Soot underneath) to build class hierarchy
        Compiler.compile();
        
        logger.info("Tai-e Engine Initialized. Application classes: {}", 
            World.get().getClassHierarchy().applicationClasses().count());
    }
}
