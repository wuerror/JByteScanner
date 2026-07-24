package com.jbytescanner.engine;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Canonical identity helpers for P0.1 Route / EntryPoint / TaintSource modeling.
 *
 * <pre>
 * RouteKey      = (HTTP method, path, Java method, parameter bindings)  // kept 1:N outside PTA
 * EntryPointKey = full Java method signature
 * SourceKey     = (kind, Java method signature, index, taint type)
 * </pre>
 */
public final class CanonicalIdentity {

    private CanonicalIdentity() {
    }

    /**
     * Deduplicates ordered raw signatures while preserving first-seen order.
     */
    public static DedupResult dedupeOrdered(List<String> rawItems) {
        if (rawItems == null || rawItems.isEmpty()) {
            return new DedupResult(0, 0, 0, List.of(), List.of());
        }
        Map<String, Integer> counts = new LinkedHashMap<>();
        List<String> unique = new ArrayList<>();
        for (String item : rawItems) {
            if (item == null || item.isBlank()) {
                continue;
            }
            Integer previous = counts.put(item, counts.getOrDefault(item, 0) + 1);
            if (previous == null) {
                unique.add(item);
            }
        }
        int raw = rawItems.stream().filter(Objects::nonNull).filter(s -> !s.isBlank()).mapToInt(s -> 1).sum();
        int uniqueCount = unique.size();
        int duplicate = Math.max(0, raw - uniqueCount);
        List<Map.Entry<String, Integer>> topDuplicates = counts.entrySet().stream()
                .filter(e -> e.getValue() > 1)
                .sorted(Map.Entry.<String, Integer>comparingByValue(Comparator.reverseOrder())
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(20)
                .collect(Collectors.toList());
        return new DedupResult(raw, uniqueCount, duplicate, List.copyOf(unique), topDuplicates);
    }

    /**
     * Builds a stable SourceKey for Tai-e taint sources.
     * SourceKey = (kind, method signature, index, taint type).
     */
    public static String sourceKey(String kind, String method, Object index, String taintType) {
        String normalizedKind = blankToEmpty(kind);
        String normalizedMethod = blankToEmpty(method);
        String normalizedIndex = index == null ? "" : String.valueOf(index).trim();
        // Blank and null taint types are equivalent: both mean "no concrete type".
        String normalizedType = blankToEmpty(taintType);
        return normalizedKind + '\0' + normalizedMethod + '\0' + normalizedIndex + '\0' + normalizedType;
    }

    private static String blankToEmpty(String value) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        return trimmed;
    }

    /**
     * Tracks unique source insertion with raw/unique/duplicate counters.
     */
    public static final class SourceCanonicalizer {
        private final Set<String> seen = new LinkedHashSet<>();
        private int raw;
        private int duplicate;

        public boolean add(String kind, String method, Object index, String taintType) {
            raw++;
            String key = sourceKey(kind, method, index, taintType);
            if (seen.add(key)) {
                return true;
            }
            duplicate++;
            return false;
        }

        public int raw() {
            return raw;
        }

        public int unique() {
            return seen.size();
        }

        public int duplicate() {
            return duplicate;
        }
    }

    public record DedupResult(
            int raw,
            int unique,
            int duplicate,
            List<String> uniqueItems,
            List<Map.Entry<String, Integer>> topDuplicates
    ) {
        public String formatTopDuplicates(int limit) {
            if (topDuplicates == null || topDuplicates.isEmpty()) {
                return "(none)";
            }
            return topDuplicates.stream()
                    .limit(limit)
                    .map(e -> e.getValue() + "x " + e.getKey())
                    .collect(Collectors.joining("; "));
        }
    }
}
