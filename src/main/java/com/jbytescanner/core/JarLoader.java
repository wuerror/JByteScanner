package com.jbytescanner.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class JarLoader {
    private static final Logger logger = LoggerFactory.getLogger(JarLoader.class);

    private static final String TEMP_DIR_PREFIX = "jbytescanner_libs_";
    
    // Ignored prefixes for inference
    private static final List<String> IGNORED_PREFIXES = List.of(
        "java.", "javax.", "sun.", "jdk.", "org.springframework.", 
        "org.apache.", "com.google.", "com.fasterxml.", "org.slf4j.",
        "ch.qos.", "org.junit.", "org.mockito.", "io.netty.",
        "com.aspose.", "com.itextpdf.", "javassist.", "org.bouncycastle.",
        "net.sf.", "org.hibernate.", "com.zaxxer."
    );

    public static class LoadedJars {
        public List<String> targetAppJars = new ArrayList<>(); // Contains target packages
        public List<String> depAppJars = new ArrayList<>();    // Other app jars (e.g. libs promoted but not target)
        public List<String> libJars = new ArrayList<>();       // Pure libs
        
        // Backward compatibility
        public List<String> getAppJars() {
            List<String> combined = new ArrayList<>(targetAppJars);
            combined.addAll(depAppJars);
            return combined;
        }
    }

    public LoadedJars loadJars(String path, List<String> scanPackages) {

        File root = new File(path);
        if (!root.exists()) {
            logger.error("Path does not exist: {}", path);
            return new LoadedJars();
        }

        List<String> rawJars = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(root.toPath())) {
            rawJars = walk.filter(p -> !Files.isDirectory(p))
                    .map(Path::toString)
                    .filter(f -> f.endsWith(".jar") || f.endsWith(".war"))
                    .collect(Collectors.toList());
        } catch (IOException e) {
            logger.error("Error walking directory: {}", path, e);
        }

        logger.info("Found {} raw JAR/WAR files in {}", rawJars.size(), path);

        return processFatJars(rawJars, scanPackages);
    }

    /**
     * Infer the main business package based on frequency of classes in App Jars.
     * Prioritizes exploded classes directories (from Fat JARs) over standalone JARs.
     */
    public String inferBasePackage(List<String> appJars) {
        Map<String, Integer> packageCounts = new HashMap<>();

        // Strategy: Prioritize directories (exploded Fat JAR classes) over JAR files
        // because directories usually contain the core business logic from BOOT-INF/classes
        boolean hasDirectories = appJars.stream().anyMatch(path -> new File(path).isDirectory());
        
        for (String jarPath : appJars) {
            File jarFile = new File(jarPath);
            
            // If we have verified business code directories, ignore potential noise from standalone JARs
            if (hasDirectories && !jarFile.isDirectory()) {
                continue;
            }

            if (jarFile.isDirectory()) {
                scanDirectoryForPackages(jarFile, "", packageCounts);
            } else {
                scanJarForPackages(jarPath, packageCounts);
            }
        }

        return packageCounts.entrySet().stream()
            .sorted((e1, e2) -> e2.getValue().compareTo(e1.getValue())) // Descending
            .map(Map.Entry::getKey)
            .findFirst()
            .orElse(null);
    }

    private void scanJarForPackages(String jarPath, Map<String, Integer> counts) {
        try (JarFile jar = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                updatePackageCount(entry.getName(), counts);
            }
        } catch (IOException e) {
            // ignore
        }
    }

    private void scanDirectoryForPackages(File dir, String currentPath, Map<String, Integer> counts) {
        File[] files = dir.listFiles();
        if (files == null) return;
        
        for (File f : files) {
            if (f.isDirectory()) {
                scanDirectoryForPackages(f, currentPath + f.getName() + "/", counts);
            } else {
                updatePackageCount(currentPath + f.getName(), counts);
            }
        }
    }

    private void updatePackageCount(String filePath, Map<String, Integer> counts) {
        if (!filePath.endsWith(".class")) return;
        
        // Convert file path to package like string
        // e.g., com/example/Foo.class -> com.example
        String pkgPath = filePath.replace('\\', '/');
        int lastSlash = pkgPath.lastIndexOf('/');
        if (lastSlash == -1) return; // default package
        
        String pkg = pkgPath.substring(0, lastSlash).replace('/', '.');
        
        // Extract top-level domain + company (e.g. com.example)
        String[] parts = pkg.split("\\.");
        if (parts.length >= 2) {
            String basePkg = parts[0] + "." + parts[1];
            
            // Check ignore list
            boolean ignored = false;
            for (String ignore : IGNORED_PREFIXES) {
                if (basePkg.startsWith(ignore) || (basePkg + ".").startsWith(ignore)) {
                    ignored = true;
                    break;
                }
            }
            
            if (!ignored) {
                counts.put(basePkg, counts.getOrDefault(basePkg, 0) + 1);
            }
        }
    }

    private LoadedJars processFatJars(List<String> rawJars, List<String> scanPackages) {
        LoadedJars result = new LoadedJars();
        File tempDir = createTempDir();

        for (String jarPath : rawJars) {
            try {
                if (isSpringFatJar(jarPath)) {
                    logger.info("Detected Spring Boot Fat JAR: {}", jarPath);
                    
                    // 1. BOOT-INF/classes -> Target App Jar (Assume it contains main logic)
                    File classesDir = new File(tempDir, new File(jarPath).getName() + "_classes");
                    classesDir.mkdirs();
                    extractBootInfClasses(jarPath, classesDir);
                    
                    // Directory is always treated as Target App Jar
                    result.targetAppJars.add(classesDir.getAbsolutePath());

                    // 2. BOOT-INF/lib/*.jar
                    File libDir = new File(tempDir, new File(jarPath).getName() + "_libs");
                    libDir.mkdirs();
                    List<String> libs = extractBootInfLibs(jarPath, libDir);
                    
                    for (String lib : libs) {
                        if (shouldPromoteToApp(lib, scanPackages)) {
                            logger.info("Promoting dependency to App Jar (Target): {}", new File(lib).getName());
                            result.targetAppJars.add(lib);
                        } else {
                            result.libJars.add(lib);
                        }
                    }
                    
                } else {
                    // Standard JAR
                    if (scanPackages == null || scanPackages.isEmpty()) {
                        // If no filter, everything is potential target (backward compat)
                        result.targetAppJars.add(jarPath);
                    } else if (shouldPromoteToApp(jarPath, scanPackages)) {
                         // If explicit package match, it is a target
                        result.targetAppJars.add(jarPath);
                    } else {
                        // Has filter but doesn't match: Treat as Library
                        logger.debug("Treating JAR as Library (No matching scan_package): {}", new File(jarPath).getName());
                        result.libJars.add(jarPath);
                    }
                }
            } catch (Exception e) {
                logger.error("Failed to process JAR: {}", jarPath, e);
                // Fallback to target to be safe, or lib? Safe to target.
                result.targetAppJars.add(jarPath);
            }
        }
        
        Runtime.getRuntime().addShutdownHook(new Thread(() -> deleteDir(tempDir)));
        return result;
    }

    /**
     * Heuristic: check if jar contains any class matching scanPackages
     */
    private boolean shouldPromoteToApp(String jarPath, List<String> scanPackages) {
        if (scanPackages == null || scanPackages.isEmpty()) {
            return false; // No filter, treat libs as libs
        }
        
        try (JarFile jar = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.endsWith(".class")) {
                    // Convert path to package: com/example/Foo.class -> com.example.Foo
                    String className = name.replace('/', '.').replace(".class", "");
                    for (String pkg : scanPackages) {
                        if (className.startsWith(pkg)) {
                            return true;
                        }
                    }
                }
            }
        } catch (IOException e) {
            logger.warn("Failed to scan jar content for promotion: {}", jarPath);
        }
        return false;
    }

    private boolean isSpringFatJar(String jarPath) {
        try (JarFile jar = new JarFile(jarPath)) {
            return jar.getEntry("BOOT-INF/classes/") != null || 
                   jar.getEntry("WEB-INF/classes/") != null;
        } catch (IOException e) {
            return false;
        }
    }

    private void extractBootInfClasses(String jarPath, File destDir) throws IOException {
        try (JarFile jar = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                
                String innerPath = null;
                if (name.startsWith("BOOT-INF/classes/")) {
                    innerPath = name.substring("BOOT-INF/classes/".length());
                } else if (name.startsWith("WEB-INF/classes/")) {
                    innerPath = name.substring("WEB-INF/classes/".length());
                }

                if (innerPath != null && !innerPath.isEmpty()) {
                    File outFile = new File(destDir, innerPath);
                    if (entry.isDirectory()) {
                        outFile.mkdirs();
                    } else {
                        outFile.getParentFile().mkdirs();
                        try (InputStream in = jar.getInputStream(entry);
                             OutputStream out = new FileOutputStream(outFile)) {
                            copy(in, out);
                        }
                    }
                }
            }
        }
    }

    private List<String> extractBootInfLibs(String jarPath, File destDir) throws IOException {
        List<String> extractedLibs = new ArrayList<>();
        try (JarFile jar = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                
                if ((name.startsWith("BOOT-INF/lib/") || name.startsWith("WEB-INF/lib/")) 
                        && name.endsWith(".jar")) {
                    
                    File outFile = new File(destDir, new File(name).getName());
                    try (InputStream in = jar.getInputStream(entry);
                         OutputStream out = new FileOutputStream(outFile)) {
                        copy(in, out);
                    }
                    extractedLibs.add(outFile.getAbsolutePath());
                }
            }
        }
        return extractedLibs;
    }

    private File createTempDir() {
        try {
            return Files.createTempDirectory(TEMP_DIR_PREFIX).toFile();
        } catch (IOException e) {
            throw new RuntimeException("Could not create temp directory for JAR unpacking", e);
        }
    }

    private void deleteDir(File dir) {
        if (dir != null && dir.exists()) {
            try (Stream<Path> walk = Files.walk(dir.toPath())) {
                walk.sorted((a, b) -> b.compareTo(a))
                    .map(Path::toFile)
                    .forEach(File::delete);
            } catch (IOException e) {
                // Ignore cleanup errors on shutdown
            }
        }
    }

    private void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
    }
}
