package com.jbytescanner.engine;

import com.jbytescanner.model.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ScaScanner {
    private static final Logger logger = LoggerFactory.getLogger(ScaScanner.class);
    
    // Pattern to match version in filename: lib-1.2.3.jar
    private static final Pattern FILENAME_VERSION = Pattern.compile("([a-zA-Z0-9\\-_]+)-(\\d+(\\.\\d+)*[a-zA-Z0-9\\-_]*)\\.jar$");

    public List<Component> scan(List<String> jarPaths) {
        List<Component> components = new ArrayList<>();
        logger.info("SCA Scanner starting on {} JARs...", jarPaths.size());
        
        for (String path : jarPaths) {
            Component comp = scanJar(path);
            if (comp != null) {
                components.add(comp);
            }
        }
        
        logger.info("SCA Scanner identified {} components.", components.size());
        return components;
    }
    
    private Component scanJar(String jarPath) {
        File file = new File(jarPath);
        if (!file.exists() || !file.getName().endsWith(".jar")) return null;
        
        // 1. Try Maven POM Properties (Most Accurate)
        try (JarFile jar = new JarFile(file)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                // META-INF/maven/group/artifact/pom.properties
                if (entry.getName().endsWith("pom.properties") && entry.getName().startsWith("META-INF/maven/")) {
                    Properties props = new Properties();
                    try (InputStream is = jar.getInputStream(entry)) {
                        props.load(is);
                        return new Component(
                            props.getProperty("groupId"),
                            props.getProperty("artifactId"),
                            props.getProperty("version"),
                            jarPath
                        );
                    }
                }
            }
            
            // 2. Try Manifest
            Manifest manifest = jar.getManifest();
            if (manifest != null) {
                Attributes attrs = manifest.getMainAttributes();
                String implTitle = attrs.getValue("Implementation-Title");
                String implVersion = attrs.getValue("Implementation-Version");
                String bundleSymName = attrs.getValue("Bundle-SymbolicName");
                
                if (implTitle != null && implVersion != null) {
                    return new Component(null, implTitle, implVersion, jarPath);
                }
                if (bundleSymName != null && implVersion != null) {
                     return new Component(null, bundleSymName, implVersion, jarPath);
                }
            }
            
        } catch (IOException e) {
            logger.warn("Failed to read JAR: {}", jarPath);
        }
        
        // 3. Fallback: Filename Parsing
        Matcher m = FILENAME_VERSION.matcher(file.getName());
        if (m.matches()) {
            return new Component(null, m.group(1), m.group(2), jarPath);
        }
        
        // 4. Just return filename as artifact
        return new Component(null, file.getName().replace(".jar", ""), null, jarPath);
    }
}
