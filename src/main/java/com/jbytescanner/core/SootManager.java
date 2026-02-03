package com.jbytescanner.core;

import soot.G;
import soot.options.Options;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class SootManager {
    private static final Logger logger = LoggerFactory.getLogger(SootManager.class);

    public static void initSoot(List<String> appJars, List<String> libJars, boolean wholeProgram, List<String> scanPackages) {
        G.reset();

        // 1. Basic Options
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_src_prec(Options.src_prec_class);
        Options.v().set_output_format(Options.output_format_none); 
        Options.v().set_keep_line_number(true);
        
        // 2. Classpath Setup
        Options.v().set_prepend_classpath(true);
        
        StringBuilder cpBuilder = new StringBuilder();
        
        // App jars + Lib jars all go to classpath
        for (String jar : appJars) cpBuilder.append(jar).append(File.pathSeparator);
        for (String jar : libJars) cpBuilder.append(jar).append(File.pathSeparator);

        Options.v().set_soot_classpath(cpBuilder.toString());
        
        // ONLY App jars go to process-dir
        Options.v().set_process_dir(appJars);
        
        // 3. Phase Options
        Options.v().set_whole_program(wholeProgram);
        
        if (wholeProgram) {
            // Strict Isolation: Only generate bodies for included packages
            Options.v().set_no_bodies_for_excluded(true);
            
            // 3.1 Whitelist (Include)
            if (scanPackages != null && !scanPackages.isEmpty()) {
                logger.info("Applying strict inclusion scope: {}", scanPackages);
                Options.v().set_include(scanPackages);
            }

            // 3.2 Blacklist (Exclude)
            List<String> excludes = new ArrayList<>();
            // Standard excludes
            excludes.add("java.");
            excludes.add("javax.");
            excludes.add("sun.");
            excludes.add("jdk.");
            excludes.add("android.");
            // Common libs that cause trouble (bloated or complex)
            excludes.add("org.slf4j.");
            excludes.add("org.apache.");
            excludes.add("com.google.");
            excludes.add("net.minidev."); 
            excludes.add("com.fasterxml.jackson.");
            excludes.add("org.springframework."); // We only analyze business logic, usually don't need deep spring bodies
            excludes.add("org.hibernate.");
            excludes.add("io.netty.");
            
            // Phase 6.3 Enhanced Exclusion List (Based on log analysis)
            excludes.add("org.bouncycastle."); // Fix crash
            excludes.add("com.sheca.");        // Fix crash
            excludes.add("com.aspose.");
            excludes.add("com.itextpdf.");
            excludes.add("oracle.");
            excludes.add("dm.jdbc.");
            excludes.add("jj2000.");
            excludes.add("com.github.jaiimageio.");
            excludes.add("com.claymoresystems.");
            
            Options.v().set_exclude(excludes);
        }
        
        // 4. Load
        logger.info("Initializing Soot... AppJars: {}, LibJars: {}", appJars.size(), libJars.size());
        Scene.v().loadNecessaryClasses();
        logger.info("Soot loaded {} classes.", Scene.v().getClasses().size());
    }
    
    // Overload for backward compatibility / discovery mode
    public static void initSoot(List<String> appJars, List<String> libJars, boolean wholeProgram) {
        initSoot(appJars, libJars, wholeProgram, null);
    }

}
