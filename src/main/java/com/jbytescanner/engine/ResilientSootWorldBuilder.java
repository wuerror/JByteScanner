package com.jbytescanner.engine;

import pascal.taie.config.AnalysisConfig;
import pascal.taie.config.Options;
import pascal.taie.frontend.soot.SootWorldBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Wraps SootWorldBuilder to add library class exclusion from Soot body construction.
 *
 * <p>Problem: Soot's TypeAssigner crashes when building Jimple bodies for library classes
 * that reference absent optional dependencies (e.g., HikariCP &rarr; Dropwizard Metrics).
 * Even with {@code -ap} (allow phantom), FastHierarchy.canStoreClass requires
 * HIERARCHY-level resolution which phantom classes can't provide.
 *
 * <p>Solution: After Tai-e's initSoot() configures Soot, inject via reflection:
 * <ul>
 *   <li>{@code set_no_bodies_for_excluded(true)} — skip body construction for excluded classes</li>
 *   <li>Dynamically-derived exclusion patterns for all library package prefixes</li>
 * </ul>
 * This ensures Soot only builds bodies for application classes while maintaining
 * hierarchy-level information for library types (sufficient for PTA + taint analysis).
 */
public class ResilientSootWorldBuilder extends SootWorldBuilder {
    private static final Logger logger = LoggerFactory.getLogger(ResilientSootWorldBuilder.class);

    private Set<String> excludePatterns = Collections.emptySet();

    public void setExcludePatterns(Set<String> patterns) {
        this.excludePatterns = patterns;
    }

    @Override
    public void build(Options options, List<AnalysisConfig> analyses) {
        // 1. Call parent's initSoot via reflection (private static)
        try {
            Method initSoot = SootWorldBuilder.class.getDeclaredMethod(
                    "initSoot", Options.class, List.class, SootWorldBuilder.class);
            initSoot.setAccessible(true);
            initSoot.invoke(null, options, analyses, this);
        } catch (InvocationTargetException e) {
            throw new RuntimeException("Failed to initialize Soot", e.getCause());
        } catch (Exception e) {
            throw new RuntimeException("Failed to call SootWorldBuilder.initSoot", e);
        }

        // 2. Inject library exclusion options BEFORE Soot processes classes.
        //    Soot is a runtime dependency (not compile), so all calls go through reflection.
        if (!excludePatterns.isEmpty()) {
            try {
                // soot.options.Options.v() → singleton
                Class<?> sootOptionsClass = Class.forName("soot.options.Options");
                Method vMethod = sootOptionsClass.getMethod("v");
                Object sootOptions = vMethod.invoke(null);

                // Get current exclude list and append ours
                Method excludeMethod = sootOptionsClass.getMethod("exclude");
                @SuppressWarnings("unchecked")
                List<String> currentExcludes = new ArrayList<>((List<String>) excludeMethod.invoke(sootOptions));
                currentExcludes.addAll(excludePatterns);

                // set_exclude(List<String>)
                Method setExclude = sootOptionsClass.getMethod("set_exclude", List.class);
                setExclude.invoke(sootOptions, currentExcludes);

                // set_no_bodies_for_excluded(true)
                Method setNoBodies = sootOptionsClass.getMethod("set_no_bodies_for_excluded", boolean.class);
                setNoBodies.invoke(sootOptions, true);

                logger.info("Added {} library exclusion patterns for Soot body construction.",
                        excludePatterns.size());
            } catch (Exception e) {
                logger.warn("Failed to set Soot exclusion options (non-fatal): {}", e.getMessage());
            }
        }

        // 3. Prepare Soot arguments (same logic as parent build())
        List<String> args = new ArrayList<>();
        Collections.addAll(args, "-cp", getClassPath(options));
        String mainClass = options.getMainClass();
        if (mainClass != null) {
            Collections.addAll(args, "-main-class", mainClass, mainClass);
        }
        args.addAll(getInputClasses(options));

        // 4. Call parent's runSoot via reflection (private static)
        try {
            Method runSoot = SootWorldBuilder.class.getDeclaredMethod(
                    "runSoot", String[].class);
            runSoot.setAccessible(true);
            runSoot.invoke(null, (Object) args.toArray(new String[0]));
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) throw (RuntimeException) cause;
            throw new RuntimeException("Soot execution failed", cause);
        } catch (Exception e) {
            throw new RuntimeException("Failed to call SootWorldBuilder.runSoot", e);
        }
    }

    /**
     * Scans library JARs and extracts 2-level package prefixes as Soot exclusion patterns.
     * Only reads JAR directory entries (no decompression), so ~300 JARs take &lt; 2 seconds.
     *
     * @param libJarPaths paths to library JARs (classPath, NOT appClassPath)
     * @param appPackages scan_packages from config (to avoid excluding app code)
     * @return set of Soot-compatible wildcard patterns (e.g., "com.zaxxer.*")
     */
    public static Set<String> deriveLibExcludes(List<String> libJarPaths, List<String> appPackages) {
        Set<String> prefixes = new TreeSet<>();
        for (String path : libJarPaths) {
            File f = new File(path);
            if (!f.isFile()) continue;
            try (JarFile jar = new JarFile(f)) {
                Enumeration<JarEntry> entries = jar.entries();
                while (entries.hasMoreElements()) {
                    String name = entries.nextElement().getName();
                    if (!name.endsWith(".class")) continue;
                    // com/zaxxer/hikari/Foo.class -> com.zaxxer
                    int first = name.indexOf('/');
                    if (first < 0) continue;
                    int second = name.indexOf('/', first + 1);
                    if (second < 0) continue;
                    prefixes.add(name.substring(0, second).replace('/', '.'));
                }
            } catch (Exception ignored) {}
        }

        // Remove prefixes that overlap with application scan packages
        if (appPackages != null) {
            for (String appPkg : appPackages) {
                String[] parts = appPkg.split("\\.");
                if (parts.length >= 2) {
                    prefixes.remove(parts[0] + "." + parts[1]);
                }
            }
        }

        Set<String> patterns = new TreeSet<>();
        for (String prefix : prefixes) {
            patterns.add(prefix + ".*");
        }
        logger.info("Derived {} library exclusion patterns from {} JARs.",
                patterns.size(), libJarPaths.size());
        return patterns;
    }
}
