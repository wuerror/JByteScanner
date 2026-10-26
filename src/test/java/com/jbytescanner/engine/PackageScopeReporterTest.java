package com.jbytescanner.engine;

import com.jbytescanner.core.JarLoader.PackageCandidate;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PackageScopeReporterTest {

    @Test
    void singlePackageIsReportedWithoutMisleadingCandidate() {
        AsmRouteExtractor.PackageEntryStats selected =
                stats(120_000, 1_200, 1_300, 1_590, 3, "srm-platform-op_classes");
        PackageScopeAdvisor.ScopeReport report = new PackageScopeAdvisor.ScopeReport(
                "org.srm", selected, Map.of("org.srm", selected),
                new PackageScopeAdvisor.Selection(List.of(), 0, false, null),
                20, 7_416);

        List<String> lines = PackageScopeReporter.describe(report);
        String text = String.join("\n", lines);
        assertTrue(text.contains("selected org.srm: classes=120000"));
        assertTrue(text.contains("routes=1590"));
        assertTrue(lines.stream().noneMatch(line -> line.startsWith("  candidate ")));
        assertTrue(text.contains("no additional application/platform package with confirmed "
                + "ASM web entries was found"));
        assertTrue(text.contains("known third-party/runtime prefixes excluded"));
    }

    @Test
    void reportsCandidateCountsSourcesUnshownAndNoHardThreshold() {
        AsmRouteExtractor.PackageEntryStats selected =
                stats(104_499, 700, 800, 1_590, 40, "srm-platform-op_classes");
        AsmRouteExtractor.PackageEntryStats hzero =
                stats(52_295, 180, 190, 5_066, 138,
                        "hzero-boot-platform-1.9.6.RELEASE.jar");
        AsmRouteExtractor.PackageEntryStats hcom =
                stats(2_000, 4, 4, 8, 6, "hcom-starter.jar");
        PackageScopeAdvisor.ScopeReport report = new PackageScopeAdvisor.ScopeReport(
                "org.srm", selected,
                Map.of("org.srm", selected, "org.hzero", hzero, "org.hcom", hcom),
                new PackageScopeAdvisor.Selection(
                        List.of(new PackageCandidate("org.hzero", 52_295),
                                new PackageCandidate("org.hcom", 2_000)),
                        6, false, null),
                20, 7_416);

        List<String> lines = PackageScopeReporter.describe(report);
        String text = String.join("\n", lines);
        assertTrue(text.contains("candidate org.hzero: classes=52295"));
        assertTrue(text.contains("routes=5066"));
        assertTrue(text.contains("sourceModules=138"));
        assertTrue(text.contains("hzero-boot-platform-1.9.6.RELEASE.jar"));
        assertTrue(text.contains("candidate org.hcom: classes=2000"));
        assertTrue(text.contains("shown: 2 of 6 additional package(s) with confirmed web "
                + "entries; unshown=4."));
        assertTrue(text.contains("run '-m api'"));
        assertTrue(text.contains("no hard inclusion threshold"));
    }

    @Test
    void unavailableEntryCountsAreNotReportedAsZero() {
        PackageScopeAdvisor.ScopeReport report = new PackageScopeAdvisor.ScopeReport(
                "org.srm", null, Map.of(),
                new PackageScopeAdvisor.Selection(List.of(), 0, true,
                        "entry scan failed: IllegalStateException"),
                20, 7_416);

        List<String> lines = PackageScopeReporter.describe(report);
        String text = String.join("\n", lines);
        assertTrue(text.contains("controllers=unavailable"));
        assertTrue(text.contains("routes=unavailable"));
        assertFalse(text.contains("routes=0"));
        assertTrue(text.contains("additional candidate detection skipped"));
    }

    private static AsmRouteExtractor.PackageEntryStats stats(
            int classes, int controllers, int webEntries, int routes,
            int sourceModules, String firstSource) {
        return new AsmRouteExtractor.PackageEntryStats(
                classes, controllers, webEntries, routes, true,
                classes, 0, sourceModules, List.of(firstSource));
    }
}
