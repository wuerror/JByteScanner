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

    private static final List<String> DEFAULT_EXCLUDES = java.util.Arrays.asList(
        // JDK & Android
        "java.", "javax.", "sun.", "jdk.", "android.", "dalvik.", "com.sun.", "org.xml.", "org.w3c.",
        
        // Logging
        "org.slf4j.", "org.apache.commons.logging.", "org.log4j.", "org.apache.logging.", "ch.qos.logback.",
        
        // Common Utils & JSON
        "com.google.", "org.apache.commons.", "com.fasterxml.jackson.", "com.alibaba.fastjson.", "com.google.gson.",
        "org.json.", "net.minidev.json.", "org.yaml.",
        
        // Spring & Frameworks (We only want to analyze the application code, not the framework internals unless needed)
        "org.springframework.", "org.hibernate.", "org.mybatis.", "org.thymeleaf.", "freemarker.",
        "org.jboss.", "org.apache.tomcat.", "org.apache.catalina.", "org.eclipse.jetty.", "io.undertow.",
        
        // Network & Async
        "io.netty.", "io.grpc.", "io.reactivex.", "rx.", "okhttp3.", "org.apache.http.",
        
        // Cloud SDKs (Huge bloat)
        "com.amazonaws.", "software.amazon.awssdk.", "com.azure.", "com.microsoft.", "com.oracle.bmc.",
        
        // Database Drivers
        "org.postgresql.", "com.mysql.", "oracle.jdbc.", "com.microsoft.sqlserver.", "org.h2.", "org.hsqldb.", 
        "org.mongodb.", "redis.clients.", "com.zaxxer.hikari.",
        
        // Crypto & Security
        "org.bouncycastle.", "com.nimbusds.", "io.jsonwebtoken.",
        
        // Languages
        "scala.", "kotlin.", "groovy.", "clojure.",
        
        // Testing
        "junit.", "org.junit.", "org.testng.", "org.mockito.", "net.bytebuddy.", "org.objenesis.",
        
        // Others
        "com.aspose.", "com.itextpdf.", "org.dom4j.", "org.jsoup."
    );

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
        
        // ONLY App jars go to process_dir
        Options.v().set_process_dir(appJars);
        
        // 3. Phase Options
        Options.v().set_whole_program(wholeProgram);
        
        if (wholeProgram) {
            // Strict Isolation: Only generate bodies for included packages
            Options.v().set_no_bodies_for_excluded(true);
            
            // 3.1 Whitelist (Include) - CRITICAL for Speed
            if (scanPackages != null && !scanPackages.isEmpty()) {
                logger.info("Applying strict inclusion scope: {}", scanPackages);
                Options.v().set_include(scanPackages);
            }

            // 3.2 Blacklist (Exclude) - Optimized List
            // Using set_exclude allows us to explicitly block these even if they are in process_dir (partially)
            // or if they are pulled in by dependencies.
            logger.info("Applying comprehensive exclude list ({} prefixes)...", DEFAULT_EXCLUDES.size());
            Options.v().set_exclude(DEFAULT_EXCLUDES);
        }
        
        // 4. Load
        logger.info("Initializing Soot... AppJars: {}, LibJars: {}", appJars.size(), libJars.size());
        Scene.v().loadNecessaryClasses();
        logger.info("Soot loaded {} classes.", Scene.v().getClasses().size());
        
        // 5. Post-Load: Force Downgrade for Leakage Classes (Double Safety)
        // Even with process_dir isolation, some shading jars (Fat Jars) might contain third-party classes 
        // in the "Application" scope. We must forcibly downgrade them if they don't match the whitelist.
        if (wholeProgram && scanPackages != null && !scanPackages.isEmpty()) {
            enforceStrictIsolation(scanPackages);
        }
    }
    
    private static void enforceStrictIsolation(List<String> scanPackages) {
        logger.info("Enforcing strict class-level isolation based on whitelist: {}", scanPackages);
        int downgraded = 0;
        int kept = 0;
        
        // Use a copy to avoid concurrent modification issues during iteration
        for (SootClass sc : new ArrayList<>(Scene.v().getApplicationClasses())) {
            if (sc.isPhantom()) continue;
            
            boolean isWhitelisted = false;
            for (String pkg : scanPackages) {
                if (sc.getName().startsWith(pkg)) {
                    isWhitelisted = true;
                    break;
                }
            }
            
            if (!isWhitelisted) {
                // Downgrade to Library Class
                sc.setLibraryClass();
                
                // CRITICAL: Release body to save memory and prevent analysis
                for (SootMethod m : sc.getMethods()) {
                    if (m.hasActiveBody()) {
                        m.releaseActiveBody();
                    }
                }
                downgraded++;
            } else {
                kept++;
            }
        }
        logger.info("Class Isolation Result: {} classes kept as Application, {} classes downgraded to Library.", kept, downgraded);
    }
    
    // Overload for backward compatibility / discovery mode
    public static void initSoot(List<String> appJars, List<String> libJars, boolean wholeProgram) {
        initSoot(appJars, libJars, wholeProgram, null);
    }

}
