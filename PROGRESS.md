# Development Progress

## Phase 1: Skeleton & Configuration [COMPLETED]
- [x] Set up Maven project structure.
- [x] Add dependencies (Soot, Picocli, Jackson, etc.).
- [x] Implement `ConfigManager` and `rules.yaml` handling.
- [x] Implement `JarLoader` for recursive scanning.
- [x] Implement Main CLI entry point.

## Phase 2: Asset Discovery Engine [COMPLETED]
- [x] Configure Soot `Scene` setup (Fixed classpath issues).
- [x] Implement `RouteExtractor`.
- [x] Implement Spring Boot Annotation Parser.
- [x] Implement Servlet/Web.xml Parser (Basic Servlet Annotation support).
- [x] Generate `api.txt` in project-specific workspace (`.jbytescanner`).
- [x] Implement **Fat JAR Support**: Auto-extract `BOOT-INF/classes` and `lib`.
- [x] Implement **Smart Jar Promotion**: Identify business jars in `BOOT-INF/lib` based on `scan_packages` config.

## Phase 2.5: Component Fingerprinting (SCA) [PENDING]
- [ ] Implement `ComponentIdentifier`.
- [ ] Extract version info from `pom.properties` or `MANIFEST.MF`.
- [ ] Output results to `components.txt`.

## Phase 3: Call Graph & Basic Data Flow [COMPLETED]
- [x] Implement `TaintEngine` skeleton.
- [x] Implement `EntryPointGenerator`: Create dummy main method calling all API routes.
- [x] Implement `CallGraphBuilder`: Configure Soot for Whole-Program analysis (CHA mode).
- [x] **Optimization**: Split ClassPath into `process-dir` (App) and `classpath` (Lib) to prevent Soot crashing on third-party libs.
- [x] **Optimization**: Implement Exclusion List for problematic libs (asm, cglib, etc.).
- [x] Implement `ReachabilityAnalyzer`: Verify source-to-sink paths on the Call Graph.

## Phase 4: Taint Analysis & Optimization [COMPLETED]
- [x] Implement `InterproceduralTaintAnalysis`: Forward taint propagation logic using CallGraph.
- [x] Integrate Sources/Sinks from `rules.yaml`.
- [x] Implement intra-procedural taint tracking (IdentityStmt + DefinitionStmt).
- [x] Implement inter-procedural taint tracking (Map args to callee params).
- [x] Verify detection of RCE and Deserialization vulnerabilities in `java-sec-code`.

## Phase 5: Reporting & Delivery [COMPLETED]
- [x] Implement `SarifReporter` (JSON generation).
- [x] Output `result.sarif` to project workspace.
- [x] Package final release.
