# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Secret Scanner (Phase 8.1)**:
    - Implemented a new "Tactical Intelligence" module for discovering hardcoded secrets.
    - **Config Scan**: Automatically scans `application.properties`, `.yml`, `.xml` inside JARs/Fat JARs for passwords, tokens, and keys.
    - **Code Scan**: Iterates over String constants in the bytecode to find AWS keys, JDBC credentials, and other secrets using Regex.
    - **Entropy Analysis**: Implemented Shannon Entropy calculation to detect high-entropy strings (e.g., random keys, large payloads).
    - **Base64 Decoding**: Detects Base64 strings, decodes them, and recursively scans the decoded content for secrets.
    - **Context-Aware Hash Detection**: Identifies hardcoded Hash credentials (MD5/SHA) by analyzing their usage context (e.g., `token.equals("hash")` or assignment to sensitive variables like `secret`, `admin`).
    - Integrated seamlessly into the main scan flow; generates `secrets.txt` in the workspace.
- **Vulnerability Scorer (Phase 8.2)**:
    - Introduced **R-S-A-C Scoring Model**: Calculates vulnerability risk based on Sink Severity, Reachability, Auth Barrier, and Confidence.
    - **Authentication Detection**: Heuristic analysis of Spring Security/Shiro annotations (`@PreAuthorize`, `@Secured`, custom `Auth`) to identify protected endpoints.
    - **Rule Categories**: Enhanced `rules.yaml` with categories (e.g., `code-exec`, `cmd-exec`, `sqli`) and default severity scores.
    - **Risk Grading**: Vulnerabilities are now graded as `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` in the SARIF report.
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
