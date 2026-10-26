package com.jbytescanner.engine;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PackageScopeAdvisorTest {

    @Test
    void selectsConfirmedWebEntryPackagesWithoutHardThresholds() {
        Map<String, AsmRouteExtractor.PackageEntryStats> stats = new LinkedHashMap<>();
        stats.put("org.srm", stats(5_690, 1_590, "srm-platform.jar"));
        stats.put("org.hzero", stats(14_136, 5_066, "hzero-boot-platform.jar"));
        stats.put("org.hcom", stats(100, 8, "hcom-starter.jar"));
        stats.put("com.zknow", stats(10, 1, "zknow-starter.jar"));
        stats.put("com.netflix", stats(15_905, 20, "eureka-core.jar"));
        stats.put("org.apache", stats(300_000, 105, "commons.jar"));
        stats.put("com.empty", new AsmRouteExtractor.PackageEntryStats(
                5_000, 0, 0, 0, true, 5_000, 0, 0, List.of()));

        PackageScopeAdvisor.Selection selection =
                PackageScopeAdvisor.selectCandidates("org.srm", stats);

        assertFalse(selection.entryDetectionSkipped());
        assertEquals(3, selection.totalCandidates());
        assertEquals(List.of("org.hzero", "org.hcom", "com.zknow"),
                selection.candidates().stream().map(c -> c.packagePrefix).toList());
    }

    @Test
    void capsShownCandidatesButReportsTotal() {
        Map<String, AsmRouteExtractor.PackageEntryStats> stats = new LinkedHashMap<>();
        stats.put("org.srm", stats(100, 100, "srm.jar"));
        for (int i = 1; i <= 6; i++) {
            stats.put("com.mod" + i, stats(100 + i, 60 - i, "mod" + i + ".jar"));
        }

        PackageScopeAdvisor.Selection selection =
                PackageScopeAdvisor.selectCandidates("org.srm", stats);

        assertFalse(selection.entryDetectionSkipped());
        assertEquals(6, selection.totalCandidates());
        assertEquals(4, selection.candidates().size());
        assertEquals(List.of("com.mod1", "com.mod2", "com.mod3", "com.mod4"),
                selection.candidates().stream().map(c -> c.packagePrefix).toList());
    }

    @Test
    void selectsCandidatesEvenWhenSelectedHasNoRoutes() {
        Map<String, AsmRouteExtractor.PackageEntryStats> stats = new LinkedHashMap<>();
        stats.put("org.srm", stats(5_690, 0, "srm.jar"));
        stats.put("org.hzero", stats(14_136, 5, "hzero.jar"));

        PackageScopeAdvisor.Selection selection =
                PackageScopeAdvisor.selectCandidates("org.srm", stats);

        assertFalse(selection.entryDetectionSkipped());
        assertEquals(List.of("org.hzero"),
                selection.candidates().stream().map(c -> c.packagePrefix).toList());
    }

    @Test
    void skipsRankingWhenSelectedEntryScanIsUnconfirmed() {
        AsmRouteExtractor.PackageEntryStats selected = new AsmRouteExtractor.PackageEntryStats(
                15_000, 0, 0, 0, false, 15_000, 7, 0, List.of());
        Map<String, AsmRouteExtractor.PackageEntryStats> stats =
                Map.of("org.srm", selected);

        PackageScopeAdvisor.Selection selection =
                PackageScopeAdvisor.selectCandidates("org.srm", stats);

        assertTrue(selection.entryDetectionSkipped());
        assertTrue(selection.skipReason().contains("unavailable"));
    }

    private static AsmRouteExtractor.PackageEntryStats stats(
            int classes, int routes, String source) {
        int controllers = Math.max(1, routes / 20);
        return new AsmRouteExtractor.PackageEntryStats(
                classes, controllers, controllers, routes, true,
                classes, 0, 1, List.of(source));
    }
}
