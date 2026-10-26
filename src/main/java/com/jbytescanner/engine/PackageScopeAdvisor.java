package com.jbytescanner.engine;

import com.jbytescanner.core.JarLoader;
import com.jbytescanner.core.JarLoader.PackageCandidate;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Discovers package-scope candidates without changing the automatic scan scope.
 *
 * <p>The selected package still comes from the legacy application-class-root
 * inference. The broader scan exists only to show a human/AI auditor which
 * platform/business packages under nested modules carry confirmed web entry
 * points. Nothing in this class writes scan_packages, api.txt, or reports.</p>
 */
public final class PackageScopeAdvisor {
    static final int MAX_CANDIDATES = 4;

    /**
     * Candidate-only exclusions. These are runtime/third-party packages that can
     * expose framework endpoints in a deployment but are not business scope
     * choices. This does not affect the legacy selected-package inference.
     */
    private static final Set<String> THIRD_PARTY_PREFIXES = Set.of(
            "com.netflix", "com.alibaba", "com.amazonaws", "com.tencentcloudapi",
            "com.oracle", "com.sun", "com.ctc", "com.bstek",
            "org.mortbay", "org.glassfish", "org.jboss", "org.quartz", "org.mule",
            "org.codehaus", "io.undertow", "io.choerodon", "springfox",
            "freemarker", "bsh", "liquibase"
    );

    private PackageScopeAdvisor() {
    }

    public record Selection(List<PackageCandidate> candidates,
                            int totalCandidates,
                            boolean entryDetectionSkipped,
                            String skipReason) {
    }

    public record ScopeReport(String selectedPackage,
                              AsmRouteExtractor.PackageEntryStats selectedStats,
                              Map<String, AsmRouteExtractor.PackageEntryStats> stats,
                              Selection selection,
                              int appRootCount,
                              int nestedModuleCount) {
    }

    public static ScopeReport analyze(String selectedPackage,
                                      List<PackageCandidate> legacyCandidates,
                                      List<String> appRoots,
                                      List<String> nestedModules) {
        if (selectedPackage == null || selectedPackage.isBlank()) {
            return new ScopeReport(null, null, Map.of(),
                    new Selection(List.of(), 0, true, "no selected package"), 0, 0);
        }
        Set<String> roots = new LinkedHashSet<>();
        if (appRoots != null) {
            roots.addAll(appRoots);
        }
        if (nestedModules != null) {
            roots.addAll(nestedModules);
        }
        Map<String, AsmRouteExtractor.PackageEntryStats> stats;
        try {
            stats = new AsmRouteExtractor(List.of(), new ArrayList<>(roots))
                    .summarizeAllEntryPoints();
        } catch (RuntimeException e) {
            return new ScopeReport(selectedPackage,
                    syntheticSelected(selectedPackage, legacyCandidates),
                    Map.of(),
                    new Selection(List.of(), 0, true,
                            "entry scan failed: " + e.getClass().getSimpleName()),
                    appRoots == null ? 0 : appRoots.size(),
                    nestedModules == null ? 0 : nestedModules.size());
        }
        return new ScopeReport(selectedPackage,
                stats.get(selectedPackage),
                stats,
                selectCandidates(selectedPackage, stats),
                appRoots == null ? 0 : appRoots.size(),
                nestedModules == null ? 0 : nestedModules.size());
    }

    static Selection selectCandidates(
            String selectedPackage,
            Map<String, AsmRouteExtractor.PackageEntryStats> stats) {
        if (selectedPackage == null || stats == null) {
            return new Selection(List.of(), 0, true, "no entry statistics");
        }
        AsmRouteExtractor.PackageEntryStats selected = stats.get(selectedPackage);
        if (selected == null || !selected.entryScanConfirmed()) {
            return new Selection(List.of(), 0, true,
                    "selected package entry counts are unavailable");
        }

        List<Map.Entry<String, AsmRouteExtractor.PackageEntryStats>> eligible = new ArrayList<>();
        for (Map.Entry<String, AsmRouteExtractor.PackageEntryStats> entry : stats.entrySet()) {
            String prefix = entry.getKey();
            AsmRouteExtractor.PackageEntryStats candidate = entry.getValue();
            if (prefix == null || prefix.equals(selectedPackage)
                    || JarLoader.isIgnoredPackagePrefix(prefix)
                    || isThirdPartyCandidatePrefix(prefix)
                    || candidate == null || !candidate.entryScanConfirmed()
                    || candidate.webEntryClasses() <= 0) {
                continue;
            }
            eligible.add(entry);
        }
        eligible.sort((a, b) -> {
            int byRoutes = Integer.compare(b.getValue().routeCount(), a.getValue().routeCount());
            if (byRoutes != 0) {
                return byRoutes;
            }
            int byClasses = Integer.compare(b.getValue().classCount(), a.getValue().classCount());
            return byClasses != 0 ? byClasses : a.getKey().compareTo(b.getKey());
        });
        List<PackageCandidate> candidates = new ArrayList<>();
        for (Map.Entry<String, AsmRouteExtractor.PackageEntryStats> entry : eligible) {
            if (candidates.size() >= MAX_CANDIDATES) {
                break;
            }
            candidates.add(new PackageCandidate(entry.getKey(), entry.getValue().classCount()));
        }
        return new Selection(candidates, eligible.size(), false, null);
    }

    static boolean isThirdPartyCandidatePrefix(String prefix) {
        if (prefix == null) {
            return false;
        }
        for (String denied : THIRD_PARTY_PREFIXES) {
            if (prefix.equals(denied) || prefix.startsWith(denied + ".")) {
                return true;
            }
        }
        return false;
    }

    private static AsmRouteExtractor.PackageEntryStats syntheticSelected(
            String selectedPackage, List<PackageCandidate> legacyCandidates) {
        int classCount = 0;
        if (legacyCandidates != null) {
            for (PackageCandidate candidate : legacyCandidates) {
                if (selectedPackage.equals(candidate.packagePrefix)) {
                    classCount = candidate.classCount;
                    break;
                }
            }
        }
        return new AsmRouteExtractor.PackageEntryStats(
                classCount, 0, 0, 0, false, 0, 0, 0, List.of());
    }
}
