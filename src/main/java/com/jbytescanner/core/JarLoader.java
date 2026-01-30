package com.jbytescanner.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class JarLoader {
    private static final Logger logger = LoggerFactory.getLogger(JarLoader.class);
    private static final String TEMP_DIR_PREFIX = "jbytescanner_libs_";

    public static class LoadedJars {
        public List<String> appJars = new ArrayList<>();
        public List<String> libJars = new ArrayList<>();
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

    private LoadedJars processFatJars(List<String> rawJars, List<String> scanPackages) {
        LoadedJars result = new LoadedJars();
        File tempDir = createTempDir();

        for (String jarPath : rawJars) {
            try {
                if (isSpringFatJar(jarPath)) {
                    logger.info("Detected Spring Boot Fat JAR: {}", jarPath);
                    
                    // 1. BOOT-INF/classes -> App Jar
                    File classesDir = new File(tempDir, new File(jarPath).getName() + "_classes");
                    classesDir.mkdirs();
                    extractBootInfClasses(jarPath, classesDir);
                    result.appJars.add(classesDir.getAbsolutePath());

                    // 2. BOOT-INF/lib/*.jar -> Check if it contains scanPackages
                    File libDir = new File(tempDir, new File(jarPath).getName() + "_libs");
                    libDir.mkdirs();
                    List<String> libs = extractBootInfLibs(jarPath, libDir);
                    
                    for (String lib : libs) {
                        if (shouldPromoteToApp(lib, scanPackages)) {
                            logger.info("Promoting dependency to App Jar: {}", new File(lib).getName());
                            result.appJars.add(lib);
                        } else {
                            result.libJars.add(lib);
                        }
                    }
                    
                } else {
                    // Standard JAR
                    if (shouldPromoteToApp(jarPath, scanPackages)) {
                        result.appJars.add(jarPath);
                    } else {
                        // If no packages specified, default everything to app jar (safe fallback)
                        // Or if specific packages specified but this jar doesn't match, maybe it's a lib?
                        // For root level jars, we usually assume they are targets unless proven otherwise.
                        result.appJars.add(jarPath);
                    }
                }
            } catch (Exception e) {
                logger.error("Failed to process JAR: {}", jarPath, e);
                result.appJars.add(jarPath);
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
