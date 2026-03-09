# Changelog

All notable changes to this project will be documented in this file.

## [1.6.1] - 2026-03-09

### Changed
- **JDBC Sink Taxonomy**:
  - Reclassified `java.sql.DriverManager.getConnection(...)` from generic `SSRF` to `JDBC_Driver_RCE` in `default_rules.yaml`.
  - Scoring now treats `jdbc_driver_rce` as a critical category; exploitability remains a human-triage decision based on actual driver and URL semantics.

### Fixed
- **False Positive: Taint Explosion via Broad Setter Tainting**:
  - `IntraTaintAnalysis.flowThrough`: Receiver tainting for `InvokeStmt` is now restricted to **setter-like methods** (`set*`, `add*`, `put*`, `append*`, `insert*`, `with*`, `push*`, `enqueue*`, `load*`, `init*`, `configure*`, `update*`, `register*`) and constructors. Previously, ANY `InstanceInvokeExpr` with a tainted argument would taint the receiver, causing taint to explode through service-layer objects (repositories, HTTP clients, APM agents) and generate hundreds of false positives.
- **False Positive: `URL.<init>` / `URI.<init>` as SSRF Sinks**:
  - Removed `<java.net.URL: void <init>(java.lang.String)>` and `<java.net.URI: void <init>(java.lang.String)>` from SSRF sinks in `default_rules.yaml`. Object construction alone does not make a network request; the real sinks (`URL.openStream()`, `URL.openConnection()`) are retained.
- **False Positive: `ObjectMapper.readValue(String, Class)` as Deserialization Sink**:
  - Removed `<com.fasterxml.jackson.databind.ObjectMapper: java.lang.Object readValue(java.lang.String,java.lang.Class)>` from deserialization sinks. Jackson's `readValue` with an explicit target class is standard safe JSON parsing, not arbitrary deserialization. Dangerous Jackson deserialization requires `enableDefaultTyping()` + polymorphic type handling, which is not modeled by this sink.
- **False Positive: Overly Broad Instance-Method Return Value Taint**:
  - `IntraTaintAnalysis.applyDefinition`: For `InstanceInvokeExpr` (instance method calls whose return value is assigned), `arg tainted → return tainted` is now restricted to **setter-like methods** (same `isSetterLike()` predicate as the receiver-tainting rule). General pass-through instance calls are handled correctly by the inter-procedural scheduler (callee is analyzed with tainted params). The `receiver tainted → return tainted` rule (for getters and chain calls) is unchanged.
  - Static invocations (`StaticInvokeExpr`) retain full `arg → return` propagation, which is correct for transformation functions (`String.format`, `Paths.get`, etc.).
- **False Positive: Receiver-Tainted Sink Check for SQL Injection**:
  - `WorklistEngine.checkSink()` and `InterproceduralTaintAnalysis`: Receiver-based sink triggering (`taintedObj.sinkMethod()`) is now **disabled for the `sqli` category**. SQLi requires a tainted SQL string argument; triggering on a tainted `Statement` or `Connection` receiver generates false positives from taint reaching database objects via field propagation. SSRF, Path_Traversal, RCE, and other categories retain receiver-based detection.

## [1.6.0] - 2026-03-09

### Added
- **Field Taint Propagation (Phase 8.5)**:
  - `IntraTaintAnalysis.flowThrough`: Any `InstanceInvokeExpr` (virtual, interface, or special/constructor) with a tainted argument now taints the receiver object. This covers the common setter pattern: `obj.setUrl(tainted)` propagates taint onto `obj` so that subsequent reads (`obj.getUrl()`, `obj.field`) stay tainted through the rest of the method.
  - `IntraTaintAnalysis`: Added `taintedStaticFields: Set<SootField>` to track writes of the form `SomeClass.field = tainted`. Subsequent reads `x = SomeClass.field` within the same method body are now correctly tainted. The set is monotone (only grows) consistent with MAY-analysis semantics.
  - `WorklistEngine.checkSink` + `InterproceduralTaintAnalysis`: Sink detection now also fires when the **receiver** of an instance-method sink is tainted (e.g., `taintedStmt.execute()`), in addition to the existing argument check. This closes a class of false negatives for builder/fluent API sink patterns.

### Fixed
- **False Negatives: Interprocedural Receiver Taint (Phase 8.5 pre-work, commit `1ca012a`)**:
  - `AnalysisState`: Added `thisTainted` boolean to the memoization key (`equals`/`hashCode`). Previously, a method entered with a tainted receiver and without a tainted receiver mapped to the same state; the second visit was silently skipped, dropping real flows.
  - `WorklistEngine.scheduleCallee` + `InterproceduralTaintAnalysis`: When an `InstanceInvokeExpr` base object is tainted, the callee's `this` local is now seeded as tainted before scheduling. This enables `source → obj (tainted) → callee(this tainted) → sink` chains.
  - `IntraTaintAnalysis.applyDefinition`: Constructor calls (`SpecialInvokeExpr.isConstructor()`) with tainted arguments now taint the base object (previously missed, leaving `new Obj(tainted)` chains broken).
  - `IntraTaintAnalysis.applyDefinition`: Static method calls (`StaticInvokeExpr`) with tainted arguments now taint the return-value local, covering `x = Utils.process(tainted)` chains that were previously dropped.
- **False Negatives: Missing JDBC URL / Connection Sinks (Phase 8.4, commit `1ca012a`)**:
  - Added `java.sql.DriverManager.getConnection(String)`, `getConnection(String, Properties)`, and `getConnection(String, String, String)` as SSRF/JDBC-URL-Injection sinks in `default_rules.yaml`.
- **Config Merge (commit `1ca012a`)**:
  - `ConfigManager`: When a workspace `rules.yaml` exists, its source/sink rules are now **merged** with the bundled defaults instead of replacing them. Rules present in the workspace file take precedence; rules only in defaults are appended. This prevents sink/source coverage regressions when users customize their rule files.
- **Graph Stability (commits `b9fc2ef`, `6e8f79b`, `ef8bc48`)**:
  - Auto-resolve dangling Soot classes during call-graph construction to reduce phantom-class noise.
  - Bulk resolution pass for recurring dangling packages.
  - Tightened retry budget for dangling resolution to avoid runaway retries.
- **JAX-RS Route Extraction**:
  - `RouteExtractor`: POJO parameters annotated with JAX-RS path/query annotations are now correctly captured in `api.txt`.
  - Added support for `@Path`, `@GET/@POST/@PUT/@DELETE/@PATCH` on JAX-RS controllers.

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
