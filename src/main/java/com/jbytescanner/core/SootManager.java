package com.jbytescanner.core;

import soot.G;
import soot.options.Options;
import soot.Scene;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Collections;
import java.util.List;

public class SootManager {
    private static final Logger logger = LoggerFactory.getLogger(SootManager.class);

    public static void initSoot(List<String> jarPaths) {
        G.reset();

        // 1. Basic Options
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_src_prec(Options.src_prec_class);
        Options.v().set_output_format(Options.output_format_none); // We don't want to write class files back
        Options.v().set_keep_line_number(true);
        
        // 2. Classpath Setup
        // Options.v().set_prepend_classpath(true) allows Soot to find the JDK's rt.jar or modules automatically
        Options.v().set_prepend_classpath(true);
        
        StringBuilder cpBuilder = new StringBuilder();
        
        // Add target jars to classpath
        for (String jar : jarPaths) {
            cpBuilder.append(jar).append(File.pathSeparator);
        }

        // We append the custom classpath to the default one
        Options.v().set_soot_classpath(cpBuilder.toString());
        Options.v().set_process_dir(jarPaths);
        
        // 3. Phase Options
        // For Discovery Phase (Phase 2), we don't strictly need full Jimple bodies for everything, 
        // but loading them ensures we can see method annotations clearly.
        // To keep it lightweight, we might disable some optimization phases.
        Options.v().set_whole_program(false); // Phase 2 is not whole program yet
        
        // 4. Load
        logger.info("Initializing Soot with {} JARs...", jarPaths.size());
        Scene.v().loadNecessaryClasses();
        logger.info("Soot loaded {} classes.", Scene.v().getClasses().size());
    }
}
