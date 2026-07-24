package com.jbytescanner.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * P0.2 classpath preflight, artifact mediation, and mixed-JAR application scope.
 *
 * <p>Produces canonical {@code targetAppJars}/{@code depAppJars}/{@code libJars} and writes
 * {@code classpath-preflight.json} before Tai-e / ASM analysis.
 */
public class ClasspathPlanner {
    private static final Logger logger = LoggerFactory.getLogger(ClasspathPlanner.class);

    /** Promote whole JAR only when almost all classes match scan packages. */
    static final double WHOLE_JAR_APP_RATIO = 0.95;

    /** Mixed extraction only pays off above this class count. */
    static final int MIXED_MIN_CLASSES = 50;

    private static final Pattern VERSIONED_JAR =
            Pattern.compile("^(?<id>.+?)-(?<ver>\\d[\\w.\\-]*)$");

    private final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public static final class PlanResult {
        public final JarLoader.LoadedJars jars;
        public final ClasspathPreflightReport report;

        public PlanResult(JarLoader.LoadedJars jars, ClasspathPreflightReport report) {
            this.jars = jars;
            this.report = report;
        }
    }

    /**
     * Canonicalize discovered jars: SHA dedup, multi-version selection, mixed-JAR extract,
     * and emit preflight report under the workspace.
     */
    public PlanResult plan(JarLoader.LoadedJars discovered,
                           List<String> scanPackages,
                           File workspaceDir) {
        ClasspathPreflightReport report = new ClasspathPreflightReport();
        report.generatedAt = Instant.now().toString();
        if (scanPackages != null) {
            report.scanPackages = new ArrayList<>(scanPackages);
        }

        File extractRoot = new File(workspaceDir, "classpath-extract");
        if (!extractRoot.exists() && !extractRoot.mkdirs()) {
            logger.warn("Could not create classpath extract dir: {}", extractRoot);
        }

        // Preserve discovery order while collecting unique absolute paths.
        LinkedHashSet<String> allPaths = new LinkedHashSet<>();
        Map<String, ArtifactDescriptor.Role> seedRoles = new LinkedHashMap<>();
        seed(discovered.targetAppJars, ArtifactDescriptor.Role.TARGET_APP, allPaths, seedRoles);
        seed(discovered.depAppJars, ArtifactDescriptor.Role.DEP_APP, allPaths, seedRoles);
        seed(discovered.libJars, ArtifactDescriptor.Role.LIBRARY, allPaths, seedRoles);

        List<ArtifactDescriptor> inspected = new ArrayList<>();
        Map<String, ArtifactDescriptor> byPath = new LinkedHashMap<>();
        for (String path : allPaths) {
            ArtifactDescriptor desc = inspect(path, scanPackages);
            desc.selectedRole = seedRoles.getOrDefault(path, ArtifactDescriptor.Role.LIBRARY);
            desc.selectionReason = "seeded-from-discovery";
            inspected.add(desc);
            byPath.put(normalizePath(path), desc);
        }

        // 1) Exact SHA-256 duplicates → keep first, drop rest.
        Map<String, ArtifactDescriptor> firstBySha = new LinkedHashMap<>();
        List<ArtifactDescriptor> afterSha = new ArrayList<>();
        for (ArtifactDescriptor desc : inspected) {
            if (desc.sha256 == null || desc.sha256.isBlank()) {
                afterSha.add(desc);
                continue;
            }
            ArtifactDescriptor first = firstBySha.get(desc.sha256);
            if (first == null) {
                firstBySha.put(desc.sha256, desc);
                afterSha.add(desc);
            } else {
                desc.selectedRole = ArtifactDescriptor.Role.DROPPED_DUPLICATE;
                desc.selectionReason = "exact-sha256-duplicate-of:" + first.path;
                report.droppedDuplicateCount++;
                report.artifacts.add(desc);
                logger.info("Dropping exact SHA-256 duplicate artifact: {} (== {})",
                        desc.fileName, first.fileName);
            }
        }

        // 2) Multi-version / same-name mediation by artifactId.
        Map<String, List<ArtifactDescriptor>> byArtifactId = new LinkedHashMap<>();
        for (ArtifactDescriptor desc : afterSha) {
            if (desc.selectedRole == ArtifactDescriptor.Role.DROPPED_DUPLICATE) {
                continue;
            }
            String id = desc.artifactId != null ? desc.artifactId : desc.fileName;
            byArtifactId.computeIfAbsent(id, ignored -> new ArrayList<>()).add(desc);
        }

        List<ArtifactDescriptor> mediated = new ArrayList<>();
        for (Map.Entry<String, List<ArtifactDescriptor>> entry : byArtifactId.entrySet()) {
            List<ArtifactDescriptor> group = entry.getValue();
            if (group.size() == 1) {
                mediated.add(group.get(0));
                continue;
            }
            mediated.addAll(selectVersionGroup(entry.getKey(), group, report));
        }

        // 3) Mixed/shaded JAR application scope.
        JarLoader.LoadedJars canonical = new JarLoader.LoadedJars();
        Map<String, List<String>> classOwners = new HashMap<>();
        int extractions = 0;

        for (ArtifactDescriptor desc : mediated) {
            if (desc.selectedRole == ArtifactDescriptor.Role.DROPPED_DUPLICATE) {
                report.artifacts.add(desc);
                continue;
            }

            boolean isDir = Files.isDirectory(Path.of(desc.path));
            boolean hasScanFilter = scanPackages != null && !scanPackages.isEmpty();

            if (!isDir && hasScanFilter && shouldExtractMixed(desc)) {
                try {
                    File outDir = new File(extractRoot, safeName(desc.fileName) + "_app_classes");
                    int extracted = extractMatchingClasses(desc.path, outDir, scanPackages);
                    if (extracted > 0) {
                        extractions++;
                        ArtifactDescriptor extractedDesc = inspect(outDir.getAbsolutePath(), scanPackages);
                        extractedDesc.selectedRole = ArtifactDescriptor.Role.EXTRACTED_APP;
                        extractedDesc.selectionReason =
                                "mixed-jar-package-extract from " + desc.fileName
                                        + " (appRatio=" + formatRatio(desc.applicationClassRatio) + ")";
                        extractedDesc.sourceArtifact = desc.path;
                        desc.selectedRole = ArtifactDescriptor.Role.LIBRARY;
                        desc.selectionReason = "mixed-jar-kept-as-library; app classes extracted to "
                                + outDir.getAbsolutePath();
                        desc.extractedTo = outDir.getAbsolutePath();
                        canonical.targetAppJars.add(outDir.getAbsolutePath());
                        canonical.libJars.add(desc.path);
                        report.artifacts.add(desc);
                        report.artifacts.add(extractedDesc);
                        // Count extracted app classes from extract dir only; for the original
                        // JAR only count non-app classes to avoid fabricated duplicate groups.
                        recordClassOwners(outDir.getAbsolutePath(), classOwners, null);
                        recordClassOwners(desc.path, classOwners, scanPackages);
                        logger.info("Mixed JAR {}: extracted {} app class file(s) to {}, kept original as library",
                                desc.fileName, extracted, outDir.getAbsolutePath());
                        continue;
                    }
                    // extracted == 0: keep seed role (do not demote TARGET_APP).
                    report.addWarning("Mixed JAR extract produced 0 classes, keeping seed role: "
                            + desc.fileName);
                } catch (IOException e) {
                    report.addWarning("Failed mixed extraction for " + desc.path
                            + "; keeping seed role: " + e.getMessage());
                    logger.warn("Mixed JAR extraction failed for {} (keeping seed role)", desc.path, e);
                }
            }

            assignToCanonical(canonical, desc);
            report.artifacts.add(desc);
            recordClassOwners(desc.path, classOwners, null);
        }

        // 4) Cross-artifact duplicate classes: report only.
        int dupGroups = 0;
        for (Map.Entry<String, List<String>> e : classOwners.entrySet()) {
            if (e.getValue().size() > 1) {
                dupGroups++;
            }
        }
        report.duplicateClassGroups = dupGroups;
        if (dupGroups > 0) {
            report.addWarning("Found " + dupGroups
                    + " class name(s) present in multiple selected artifacts (reported only, not removed).");
        }

        report.mixedJarExtractions = extractions;
        report.targetAppCount = canonical.targetAppJars.size();
        report.depAppCount = canonical.depAppJars.size();
        report.libraryCount = canonical.libJars.size();

        writeReport(workspaceDir, report);
        logger.info("Classpath preflight: target={}, depApp={}, lib={}, droppedDup={}, mixedExtract={}, "
                        + "duplicateClassGroups={}, warnings={}",
                report.targetAppCount, report.depAppCount, report.libraryCount,
                report.droppedDuplicateCount, report.mixedJarExtractions,
                report.duplicateClassGroups, report.warnings.size());

        return new PlanResult(canonical, report);
    }

    private void seed(List<String> paths, ArtifactDescriptor.Role role,
                      LinkedHashSet<String> allPaths,
                      Map<String, ArtifactDescriptor.Role> seedRoles) {
        if (paths == null) {
            return;
        }
        for (String path : paths) {
            if (path == null || path.isBlank()) {
                continue;
            }
            String abs = normalizePath(path);
            allPaths.add(abs);
            // Prefer TARGET_APP if any seed says so.
            ArtifactDescriptor.Role existing = seedRoles.get(abs);
            if (existing == null || role == ArtifactDescriptor.Role.TARGET_APP) {
                seedRoles.put(abs, role);
            }
        }
    }

    private List<ArtifactDescriptor> selectVersionGroup(String artifactId,
                                                        List<ArtifactDescriptor> group,
                                                        ClasspathPreflightReport report) {
        // Same version string + different SHA → conflict, keep first, warn.
        Map<String, List<ArtifactDescriptor>> byVersion = new LinkedHashMap<>();
        for (ArtifactDescriptor desc : group) {
            String ver = desc.manifestVersion != null ? desc.manifestVersion : "unknown";
            byVersion.computeIfAbsent(ver, ignored -> new ArrayList<>()).add(desc);
        }

        List<ArtifactDescriptor> kept = new ArrayList<>();
        for (Map.Entry<String, List<ArtifactDescriptor>> verEntry : byVersion.entrySet()) {
            List<ArtifactDescriptor> sameVer = verEntry.getValue();
            if (sameVer.size() == 1) {
                kept.add(sameVer.get(0));
                continue;
            }
            Set<String> hashes = new HashSet<>();
            for (ArtifactDescriptor d : sameVer) {
                if (d.sha256 != null) {
                    hashes.add(d.sha256);
                }
            }
            if (hashes.size() > 1) {
                report.addWarning("Same artifactId+version different content: " + artifactId
                        + " version=" + verEntry.getKey() + " paths="
                        + sameVer.stream().map(d -> d.path).toList());
            }
            ArtifactDescriptor first = sameVer.get(0);
            first.selectionReason = (first.selectionReason == null ? "" : first.selectionReason + "; ")
                    + "same-name-version-keep-first";
            kept.add(first);
            for (int i = 1; i < sameVer.size(); i++) {
                ArtifactDescriptor drop = sameVer.get(i);
                drop.selectedRole = ArtifactDescriptor.Role.DROPPED_DUPLICATE;
                drop.selectionReason = "same-name-version-dropped-keep-first:" + first.path;
                report.droppedDuplicateCount++;
                report.artifacts.add(drop);
            }
        }

        if (kept.size() == 1) {
            report.addVersionSelection(artifactId, kept.get(0).path, "single-after-same-version-collapse");
            return kept;
        }

        // Multi-version: prefer higher version (explicit strategy).
        kept.sort(Comparator.comparing((ArtifactDescriptor d) ->
                d.manifestVersion == null ? "" : d.manifestVersion, this::compareVersions).reversed());
        ArtifactDescriptor chosen = kept.get(0);
        chosen.selectionReason = (chosen.selectionReason == null ? "" : chosen.selectionReason + "; ")
                + "multi-version-prefer-newer";
        report.addVersionSelection(artifactId, chosen.path,
                "prefer-newer over "
                        + kept.stream().skip(1).map(d -> d.manifestVersion + "@" + d.fileName).toList());
        List<ArtifactDescriptor> result = new ArrayList<>();
        result.add(chosen);
        for (int i = 1; i < kept.size(); i++) {
            ArtifactDescriptor drop = kept.get(i);
            drop.selectedRole = ArtifactDescriptor.Role.DROPPED_DUPLICATE;
            drop.selectionReason = "multi-version-dropped-prefer-newer:" + chosen.path;
            report.droppedDuplicateCount++;
            report.artifacts.add(drop);
            logger.info("Multi-version drop {} ({}), kept {} ({})",
                    drop.fileName, drop.manifestVersion, chosen.fileName, chosen.manifestVersion);
        }
        return result;
    }

    private void assignToCanonical(JarLoader.LoadedJars jars, ArtifactDescriptor desc) {
        switch (desc.selectedRole) {
            case TARGET_APP, EXTRACTED_APP -> jars.targetAppJars.add(desc.path);
            case DEP_APP -> jars.depAppJars.add(desc.path);
            case LIBRARY -> jars.libJars.add(desc.path);
            default -> {
                // dropped already recorded
            }
        }
    }

    static boolean shouldExtractMixed(ArtifactDescriptor desc) {
        return desc.classCount >= MIXED_MIN_CLASSES
                && desc.applicationClassCount > 0
                && desc.applicationClassCount < desc.classCount
                && desc.applicationClassRatio < WHOLE_JAR_APP_RATIO;
    }

    ArtifactDescriptor inspect(String path, List<String> scanPackages) {
        ArtifactDescriptor desc = new ArtifactDescriptor();
        Path p = Path.of(path).toAbsolutePath().normalize();
        desc.path = p.toString();
        desc.fileName = p.getFileName() != null ? p.getFileName().toString() : desc.path;
        try {
            if (Files.isDirectory(p)) {
                desc.size = directorySize(p);
                desc.sha256 = hashDirectoryClasses(p);
                inspectDirectoryClasses(p, desc, scanPackages);
            } else {
                desc.size = Files.size(p);
                desc.sha256 = hashFile(p);
                inspectJar(p, desc, scanPackages);
            }
        } catch (Exception e) {
            logger.warn("Failed to inspect artifact {}: {}", path, e.toString());
            desc.selectionReason = "inspect-failed:" + e.getMessage();
        }
        parseArtifactIdentity(desc);
        if (desc.classCount > 0) {
            desc.applicationClassRatio = (double) desc.applicationClassCount / (double) desc.classCount;
        }
        return desc;
    }

    private void inspectJar(Path jarPath, ArtifactDescriptor desc, List<String> scanPackages)
            throws IOException {
        Map<String, Integer> hist = new LinkedHashMap<>();
        Set<String> classNames = new HashSet<>();
        int classes = 0;
        int appClasses = 0;
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Manifest manifest = jar.getManifest();
            if (manifest != null) {
                Attributes main = manifest.getMainAttributes();
                String ver = firstNonBlank(
                        main.getValue(Attributes.Name.IMPLEMENTATION_VERSION),
                        main.getValue("Bundle-Version"),
                        main.getValue(Attributes.Name.SPECIFICATION_VERSION));
                if (ver != null) {
                    desc.manifestVersion = ver.trim();
                }
            }
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                    continue;
                }
                if (entry.getName().contains("BOOT-INF/") || entry.getName().contains("WEB-INF/")) {
                    // Nested fat content is handled by JarLoader extraction; skip nested counts.
                    continue;
                }
                classes++;
                String className = entry.getName().replace('/', '.').replace(".class", "");
                if (!classNames.add(className)) {
                    desc.duplicateClassCount++;
                }
                String pkg2 = twoLevelPackage(className);
                if (pkg2 != null) {
                    hist.put(pkg2, hist.getOrDefault(pkg2, 0) + 1);
                }
                if (matchesScanPackage(className, scanPackages)) {
                    appClasses++;
                }
            }
        }
        desc.classCount = classes;
        desc.applicationClassCount = appClasses;
        desc.packageHistogram = topHistogram(hist, 30);
    }

    private void inspectDirectoryClasses(Path dir, ArtifactDescriptor desc, List<String> scanPackages)
            throws IOException {
        Map<String, Integer> hist = new LinkedHashMap<>();
        Set<String> classNames = new HashSet<>();
        int classes = 0;
        int appClasses = 0;
        try (Stream<Path> walk = Files.walk(dir)) {
            List<Path> classFiles = walk.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(".class"))
                    .toList();
            for (Path classFile : classFiles) {
                classes++;
                String rel = dir.relativize(classFile).toString().replace('\\', '/');
                String className = rel.replace('/', '.').replace(".class", "");
                if (!classNames.add(className)) {
                    desc.duplicateClassCount++;
                }
                String pkg2 = twoLevelPackage(className);
                if (pkg2 != null) {
                    hist.put(pkg2, hist.getOrDefault(pkg2, 0) + 1);
                }
                if (matchesScanPackage(className, scanPackages)) {
                    appClasses++;
                }
            }
        }
        desc.classCount = classes;
        desc.applicationClassCount = appClasses;
        desc.packageHistogram = topHistogram(hist, 30);
    }

    private int extractMatchingClasses(String jarPath, File outDir, List<String> scanPackages)
            throws IOException {
        if (outDir.exists()) {
            deleteRecursively(outDir.toPath());
        }
        Path outRoot = outDir.toPath().toAbsolutePath().normalize();
        Files.createDirectories(outRoot);
        int extracted = 0;
        try (JarFile jar = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                    continue;
                }
                String entryName = entry.getName().replace('\\', '/');
                if (entryName.startsWith("/") || entryName.contains("..")) {
                    logger.warn("Skipping unsafe jar entry path: {}", entryName);
                    continue;
                }
                String className = entryName.replace('/', '.').replace(".class", "");
                if (!matchesScanPackage(className, scanPackages)) {
                    continue;
                }
                Path out = outRoot.resolve(entryName).normalize();
                if (!out.startsWith(outRoot)) {
                    logger.warn("Skipping zip-slip entry: {}", entryName);
                    continue;
                }
                Files.createDirectories(out.getParent());
                try (InputStream in = jar.getInputStream(entry);
                     OutputStream outStream = Files.newOutputStream(out)) {
                    in.transferTo(outStream);
                }
                extracted++;
            }
        }
        return extracted;
    }

    /**
     * @param excludeMatchingPackages when non-null, skip classes matching these packages
     *                                (used so mixed-JAR originals do not double-count extracted app classes)
     */
    private void recordClassOwners(String path, Map<String, List<String>> classOwners,
                                   List<String> excludeMatchingPackages) {
        try {
            Path p = Path.of(path);
            if (Files.isDirectory(p)) {
                try (Stream<Path> walk = Files.walk(p)) {
                    walk.filter(Files::isRegularFile)
                            .filter(f -> f.getFileName().toString().endsWith(".class"))
                            .forEach(f -> {
                                String rel = p.relativize(f).toString().replace('\\', '/');
                                String className = rel.replace('/', '.').replace(".class", "");
                                if (matchesScanPackage(className, excludeMatchingPackages)) {
                                    return;
                                }
                                classOwners.computeIfAbsent(rel, ignored -> new ArrayList<>()).add(path);
                            });
                }
            } else if (path.endsWith(".jar") || path.endsWith(".war")) {
                try (JarFile jar = new JarFile(path)) {
                    Enumeration<JarEntry> entries = jar.entries();
                    while (entries.hasMoreElements()) {
                        JarEntry entry = entries.nextElement();
                        if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                            continue;
                        }
                        String entryName = entry.getName();
                        String className = entryName.replace('/', '.').replace(".class", "");
                        if (matchesScanPackage(className, excludeMatchingPackages)) {
                            continue;
                        }
                        classOwners.computeIfAbsent(entryName, ignored -> new ArrayList<>()).add(path);
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("class-owner scan skipped for {}: {}", path, e.toString());
        }
    }

    private void writeReport(File workspaceDir, ClasspathPreflightReport report) {
        try {
            File out = new File(workspaceDir, "classpath-preflight.json");
            mapper.writeValue(out, report);
            logger.info("Wrote classpath preflight report: {}", out.getAbsolutePath());
        } catch (IOException e) {
            logger.error("Failed to write classpath-preflight.json", e);
        }
    }

    private void parseArtifactIdentity(ArtifactDescriptor desc) {
        String base = desc.fileName;
        if (base == null) {
            return;
        }
        if (base.endsWith(".jar") || base.endsWith(".war")) {
            base = base.substring(0, base.lastIndexOf('.'));
        }
        Matcher m = VERSIONED_JAR.matcher(base);
        if (m.matches()) {
            desc.artifactId = m.group("id");
            if (desc.manifestVersion == null || desc.manifestVersion.isBlank()) {
                desc.manifestVersion = m.group("ver");
            }
        } else {
            desc.artifactId = base;
        }
    }

    static boolean matchesScanPackage(String className, List<String> scanPackages) {
        if (scanPackages == null || scanPackages.isEmpty() || className == null) {
            return false;
        }
        for (String pkg : scanPackages) {
            if (pkg == null || pkg.isBlank()) {
                continue;
            }
            if (className.equals(pkg) || className.startsWith(pkg + ".")) {
                return true;
            }
        }
        return false;
    }

    private static String twoLevelPackage(String className) {
        String[] parts = className.split("\\.");
        if (parts.length >= 2) {
            return parts[0] + "." + parts[1];
        }
        return parts.length == 1 ? parts[0] : null;
    }

    private static Map<String, Integer> topHistogram(Map<String, Integer> hist, int limit) {
        return hist.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(limit)
                .collect(LinkedHashMap::new,
                        (m, e) -> m.put(e.getKey(), e.getValue()),
                        Map::putAll);
    }

    private String hashFile(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(path);
             DigestInputStream din = new DigestInputStream(in, digest)) {
            din.transferTo(OutputStream.nullOutputStream());
        }
        return toHex(digest.digest());
    }

    private String hashDirectoryClasses(Path dir) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (Stream<Path> walk = Files.walk(dir)) {
            List<Path> files = walk.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(".class"))
                    .sorted()
                    .toList();
            for (Path file : files) {
                digest.update(dir.relativize(file).toString().replace('\\', '/').getBytes());
                digest.update(Files.readAllBytes(file));
            }
        }
        return toHex(digest.digest());
    }

    private long directorySize(Path dir) throws IOException {
        try (Stream<Path> walk = Files.walk(dir)) {
            return walk.filter(Files::isRegularFile)
                    .mapToLong(p -> {
                        try {
                            return Files.size(p);
                        } catch (IOException e) {
                            return 0L;
                        }
                    })
                    .sum();
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format(Locale.ROOT, "%02x", b));
        }
        return sb.toString();
    }

    private static String normalizePath(String path) {
        return Path.of(path).toAbsolutePath().normalize().toString();
    }

    private static String safeName(String fileName) {
        return fileName.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    private static String formatRatio(double ratio) {
        return String.format(Locale.ROOT, "%.3f", ratio);
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    /**
     * Compare dotted versions; non-numeric tails are compared lexicographically.
     * Higher is newer. Empty is lowest.
     */
    int compareVersions(String a, String b) {
        if (a == null || a.isBlank()) {
            return b == null || b.isBlank() ? 0 : -1;
        }
        if (b == null || b.isBlank()) {
            return 1;
        }
        String[] pa = a.split("[.\\-_]");
        String[] pb = b.split("[.\\-_]");
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            String sa = i < pa.length ? pa[i] : "0";
            String sb = i < pb.length ? pb[i] : "0";
            if (sa.isEmpty()) {
                sa = "0";
            }
            if (sb.isEmpty()) {
                sb = "0";
            }
            boolean na = sa.chars().allMatch(Character::isDigit);
            boolean nb = sb.chars().allMatch(Character::isDigit);
            if (na && nb) {
                int cmp = Integer.compare(Integer.parseInt(sa), Integer.parseInt(sb));
                if (cmp != 0) {
                    return cmp;
                }
            } else {
                int cmp = sa.compareToIgnoreCase(sb);
                if (cmp != 0) {
                    return cmp;
                }
            }
        }
        return 0;
    }

    private static void deleteRecursively(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(root)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // best effort
                }
            });
        }
    }
}
