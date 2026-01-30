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

    public List<String> loadJars(String path) {
        File root = new File(path);
        if (!root.exists()) {
            logger.error("Path does not exist: {}", path);
            return new ArrayList<>();
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

        // Process Fat JARs: Unpack BOOT-INF/classes and BOOT-INF/lib if detected
        return processFatJars(rawJars);
    }

    private List<String> processFatJars(List<String> rawJars) {
        List<String> processedClasspath = new ArrayList<>();
        File tempDir = createTempDir();

        for (String jarPath : rawJars) {
            try {
                if (isSpringFatJar(jarPath)) {
                    logger.info("Detected Spring Boot Fat JAR: {}", jarPath);
                    // 1. Unpack BOOT-INF/classes -> acts as the application code
                    File classesDir = new File(tempDir, new File(jarPath).getName() + "_classes");
                    classesDir.mkdirs();
                    extractBootInfClasses(jarPath, classesDir);
                    processedClasspath.add(classesDir.getAbsolutePath());

                    // 2. Unpack BOOT-INF/lib/*.jar -> dependencies
                    File libDir = new File(tempDir, new File(jarPath).getName() + "_libs");
                    libDir.mkdirs();
                    List<String> libs = extractBootInfLibs(jarPath, libDir);
                    processedClasspath.addAll(libs);
                    
                } else {
                    // Standard JAR, just add to classpath
                    processedClasspath.add(jarPath);
                }
            } catch (Exception e) {
                logger.error("Failed to process JAR: {}", jarPath, e);
                // Fallback: add original jar
                processedClasspath.add(jarPath);
            }
        }
        
        // Add a shutdown hook to clean up temp dir
        Runtime.getRuntime().addShutdownHook(new Thread(() -> deleteDir(tempDir)));
        
        return processedClasspath;
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
                walk.sorted((a, b) -> b.compareTo(a)) // Delete leaves first
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
