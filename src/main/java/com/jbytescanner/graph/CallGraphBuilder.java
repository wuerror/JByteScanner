package com.jbytescanner.graph;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.options.Options;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CallGraphBuilder {
    private static final Logger logger = LoggerFactory.getLogger(CallGraphBuilder.class);
    private static final int MAX_DANGLING_RESOLUTION = 10;
    private static final int BULK_PACKAGE_THRESHOLD = 3;
    private static final int BULK_MAX_CLASSES = 400;
    private static final Pattern DANGLING_PATTERN =
            Pattern.compile("but\\s+([\\w.$/]+)\\s+is at resolving level DANGLING");
    private final Map<String, Integer> packageDanglingHits = new HashMap<>();
    private final Set<String> bulkResolvedPackages = new HashSet<>();

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

                maybeBulkResolvePackage(danglingClass);

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

    private void maybeBulkResolvePackage(String className) {
        String pkg = getPackageName(className);
        if (pkg == null) {
            return;
        }

        int hits = packageDanglingHits.merge(pkg, 1, Integer::sum);
        if (hits < BULK_PACKAGE_THRESHOLD || !bulkResolvedPackages.add(pkg)) {
            return;
        }

        logger.info("Package '{}' triggered {} dangling hits. Bulk resolving to cut retries.", pkg, hits);
        List<String> classes = findClassesInPackage(pkg);
        if (classes.isEmpty()) {
            logger.warn("Bulk resolve skipped. No class files found for package {} on classpath.", pkg);
            return;
        }

        int resolvedCount = 0;
        for (String candidate : classes) {
            if (resolvedCount >= BULK_MAX_CLASSES) {
                logger.info("Reached bulk resolve cap of {} classes for package {}. Stopping.", BULK_MAX_CLASSES, pkg);
                break;
            }
            try {
                Scene.v().forceResolve(candidate, SootClass.HIERARCHY);
                resolvedCount++;
            } catch (RuntimeException e) {
                logger.debug("Bulk resolve failed for {}: {}", candidate, e.toString());
            }
        }
        logger.info("Bulk resolved {} classes under package {} to avoid future dangling errors.", resolvedCount, pkg);
    }

    private List<String> findClassesInPackage(String packageName) {
        String classpath = Options.v().soot_classpath();
        if (classpath == null || classpath.isEmpty()) {
            return List.of();
        }

        String pkgPath = packageName.replace('.', '/') + "/";
        List<String> found = new ArrayList<>();
        String[] entries = classpath.split(File.pathSeparator);
        for (String entry : entries) {
            if (entry == null || entry.isEmpty()) {
                continue;
            }
            File cpEntry = new File(entry);
            if (!cpEntry.exists()) {
                continue;
            }
            try {
                if (cpEntry.isDirectory()) {
                    File pkgDir = new File(cpEntry, pkgPath);
                    if (pkgDir.exists() && pkgDir.isDirectory()) {
                        collectClassesFromDirectory(pkgDir.toPath(), packageName, found);
                    }
                } else if (entry.endsWith(".jar")) {
                    collectClassesFromJar(cpEntry, pkgPath, found);
                }
            } catch (IOException ioe) {
                logger.debug("Failed to scan classpath entry {} for package {}: {}", entry, packageName, ioe.toString());
            }

            if (found.size() >= BULK_MAX_CLASSES) {
                break;
            }
        }
        return found;
    }

    private void collectClassesFromDirectory(Path pkgDir, String packageName, List<String> collector) throws IOException {
        try (var stream = Files.walk(pkgDir)) {
            var iterator = stream.filter(p -> Files.isRegularFile(p) && p.toString().endsWith(".class")).iterator();
            while (iterator.hasNext() && collector.size() < BULK_MAX_CLASSES) {
                Path path = iterator.next();
                String rel = pkgDir.relativize(path).toString().replace('\\', '/');
                String className = packageName + '.' + rel.replace('/', '.').replace(".class", "");
                collector.add(className);
            }
        }
    }

    private void collectClassesFromJar(File jarFile, String pkgPath, List<String> collector) throws IOException {
        try (JarFile jar = new JarFile(jarFile)) {
            var entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName();
                if (!name.startsWith(pkgPath) || !name.endsWith(".class")) {
                    continue;
                }
                String className = name.replace('/', '.').replace(".class", "");
                collector.add(className);
                if (collector.size() >= BULK_MAX_CLASSES) {
                    return;
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

    private String getPackageName(String className) {
        int idx = className.lastIndexOf('.');
        if (idx <= 0) {
            return null;
        }
        return className.substring(0, idx);
    }
}
