# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Worklist Analysis Engine (Phase 7.2)**:
    - Introduced `WorklistEngine` to replace the recursive `InterproceduralTaintAnalysis`.
    - Solves potential StackOverflowError on deep call chains.
    - Implemented "Leaf Summary Optimization": Automatically identifies leaf methods in the Call Graph and applies cached summaries instead of scheduling them for analysis.
    - Switched `TaintEngine` to use `WorklistEngine` by default.
- **Method Summary Integration (Phase 7.1)**:
    - Integrated `SummaryGenerator` into `InterproceduralTaintAnalysis` loop.
    - Implemented caching of method summaries (`MethodSummary`) during analysis to support future worklist-based engine.
    - Summaries now capture intra-procedural taint flow (params to return/sinks) for each visited method.
- **Refactor AnalysisState (Phase 6.1)**:
    - Replaced inefficient String-based memoization key in `InterproceduralTaintAnalysis` with a structured `AnalysisState` object.
    - Utilized `BitSet` for efficient storage of tainted parameter indices, reducing memory footprint during deep recursion.
- **Strict Dependency Isolation (Phase 6.3)**:
    - Refactored `JarLoader` to explicitly distinguish between "Target Jars" (matching `scan_packages`) and "Library Jars".
    - Target Jars are now loaded into Soot's `process_dir` (generating Jimple bodies), while Library Jars are loaded into `classpath` (signatures only).
    - This architecture prevents crashes and significantly improves stability when analyzing complex third-party libraries (e.g., `com.itextpdf`, `org.bouncycastle`).
    - Spring Boot `BOOT-INF/classes` is automatically treated as Target.

### Fixed
- **NPE in RuleManager**: Fixed `NullPointerException` when processing CallGraph edges where `target()` method is null during Backward Reachability Analysis.
- **DiscoveryEngine Compilation**: Fixed variable reference error (`appJars` -> `targetAppJars`).
