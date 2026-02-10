# Changelog

All notable changes to this project will be documented in this file.

## [1.5.0] - 2026-02-10

### Added
- **Legacy Web App Support (Phase 10.1)**:
    - Implemented `WebXmlParser` to extract Servlet mappings from `web.xml` files in JAR/WAR archives.
    - Updated `RouteExtractor` to merge `web.xml` routes with Spring annotation-based routes.
    - Enhanced `DiscoveryEngine` to scan all available JARs (including libraries) for `web.xml` definitions, ensuring routes in dependencies (e.g., `bos-resources.jar`) are discovered.
    - Fixes issue where legacy Servlet routes were missed in hybrid Spring Boot + Servlet applications.

## [1.4.0] - 2026-02-09

### Added
- **Smart PoC Generator (Phase 8.3)**:
    - Implemented `PoCGenerator` to automatically create ready-to-use HTTP request payloads for discovered vulnerabilities.
    - **Context-Aware Generation**: Generates correct `Content-Type` (JSON, Form-UrlEncoded, Multipart) based on Spring annotations (`@RequestBody`, `@RequestParam`).
    - **Payload Injection**: Automatically injects vulnerability-specific payloads (e.g., `whoami` for RCE, `1=1` for SQLi) into the appropriate parameters.
    - **ApiRoute Metadata**: Enhanced `api.txt` and `DiscoveryEngine` to capture and persist parameter types, names, and annotations.
    - Generates `generated_pocs.txt` which can be directly imported into Burp Suite Repeater.
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
- **Gadget Suggestion Engine (Phase 9.2)**:
    - Implemented `GadgetInspector` to analyze library dependencies and suggest usable Deserialization Gadget Chains.
    - **Database**: Integrated a database of 400+ known gadgets extracted from `java-chains` tool.
    - **SCA**: Implemented lightweight SCA (Software Composition Analysis) to parse `pom.properties` and JAR filenames for dependency versioning.
    - **Reporting**: Generates a grouped report `gadgets.txt` mapping available libraries to potential exploit chains.
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

### Optimized
- **Call Graph Generation (Strategy A)**:
    - Optimized `SootManager` to apply strict exclusions *before* loading classes.
    - Extended the default exclusion list to filter out massive frameworks (Spring internals, AWS/Azure SDKs, Netty, etc.) from analysis scope.
    - Significantly reduced `wjtp` phase execution time and memory usage.

### Fixed
- **NPE in RuleManager**: Fixed `NullPointerException` when processing CallGraph edges where `target()` method is null during Backward Reachability Analysis.
- **DiscoveryEngine Compilation**: Fixed variable reference error (`appJars` -> `targetAppJars`).
- **Secret Scanner Regex**: Improved regex to better capture keys like `encrypt.key`, `private_key`.
