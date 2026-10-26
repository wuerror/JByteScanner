package com.jbytescanner.engine;

import com.jbytescanner.core.JarLoader.PackageCandidate;

import java.util.ArrayList;
import java.util.List;

/**
 * Formats bounded, stable package-scope guidance for the ordinary scan log.
 *
 * <p>This class is presentation-only: it never changes scan_packages, api.txt,
 * or the reports. The selected package remains the only automatically added
 * scope.</p>
 */
public final class PackageScopeReporter {
    private PackageScopeReporter() {
    }

    public static List<String> describe(PackageScopeAdvisor.ScopeReport report) {
        List<String> lines = new ArrayList<>();
        if (report == null || report.selectedPackage() == null) {
            return lines;
        }
        lines.add("Package scope candidates (selected by legacy application-class-root inference; "
                + "candidate scan covers application class roots + nested BOOT-INF/lib modules; "
                + "known third-party/runtime prefixes excluded):");
        lines.add("  scope: appClassRoots=" + report.appRootCount()
                + ", nestedModules=" + report.nestedModuleCount()
                + "; classes=unique application/platform .class names under the 2-segment prefix "
                + "(duplicate module copies collapsed); controllers=@Controller/@RestController; "
                + "webEntries=controller/servlet/JAX-RS classes; routes=declared ASM routes "
                + "(web.xml routes not package-attributed)");
        lines.add("  selected " + report.selectedPackage() + ": "
                + entryDescription(report.selectedStats()));

        PackageScopeAdvisor.Selection selection = report.selection();
        if (selection == null || selection.entryDetectionSkipped()) {
            lines.add("  additional candidate detection skipped: "
                    + (selection == null ? "no selection" : selection.skipReason())
                    + "; no zero-entry claim is made.");
            return lines;
        }
        List<PackageCandidate> candidates = selection.candidates();
        if (candidates == null || candidates.isEmpty()) {
            lines.add("  no additional application/platform package with confirmed ASM web entries "
                    + "was found (known third-party/runtime prefixes excluded).");
            return lines;
        }
        for (PackageCandidate candidate : candidates) {
            AsmRouteExtractor.PackageEntryStats stats = report.stats() == null
                    ? null : report.stats().get(candidate.packagePrefix);
            lines.add("  candidate " + candidate.packagePrefix + ": "
                    + entryDescription(stats));
        }
        lines.add("  shown: " + candidates.size() + " of " + selection.totalCandidates()
                + " additional package(s) with confirmed web entries; unshown="
                + (selection.totalCandidates() - candidates.size()) + ".");
        lines.add("  Only the selected package was auto-added to scan_packages. To include a "
                + "candidate, add it to rules.yaml scan_packages, run '-m api' to regenerate "
                + "api.txt, then rerun the scan.");
        lines.add("  Candidates are ordered by detected routes, then classes; no hard inclusion "
                + "threshold is applied.");
        return lines;
    }

    private static String entryDescription(AsmRouteExtractor.PackageEntryStats stats) {
        if (stats == null) {
            return "classes=unavailable controllers=unavailable webEntries=unavailable "
                    + "routes=unavailable";
        }
        if (!stats.entryScanConfirmed()) {
            return "classes=" + stats.classCount()
                    + " controllers=unavailable webEntries=unavailable routes=unavailable "
                    + "(entry scan partial: scannedClasses=" + stats.scannedClasses()
                    + ", failedClasses=" + stats.failedClasses() + ")";
        }
        StringBuilder text = new StringBuilder()
                .append("classes=").append(stats.classCount())
                .append(" controllers=").append(stats.controllerClasses())
                .append(" webEntries=").append(stats.webEntryClasses())
                .append(" routes=").append(stats.routeCount());
        if (stats.sourceModuleCount() > 0) {
            text.append(" sourceModules=").append(stats.sourceModuleCount());
            if (!stats.sourceModules().isEmpty()) {
                text.append(" [").append(String.join(", ", stats.sourceModules())).append("]");
            }
        }
        return text.toString();
    }
}
