# Development Plan

This plan ensures the project can be seamlessly continued by other AI agents or developers.

## Phase 1: Skeleton & Configuration [COMPLETED]
*   **Tasks**:
    *   Set up Maven project. Dependencies: `soot-4.5.0` (or newer), `jackson-dataformat-yaml`, `picocli` (CLI args).
    *   Implement `ConfigManager`: Handle extraction/loading of `rules.yaml`.
    *   Implement `JarLoader`: Recursive directory scanning, ZipInputStream handling for nested jars.
*   **Deliverable**: A CLI tool that can read a directory of JARs and print the loaded configuration.

## Phase 2: Asset Discovery Engine [COMPLETED]
*   **Tasks**:
    *   Configure Soot environment (`Scene`, `SootClass`).
    *   Implement `RouteExtractor`: Iterate `Scene.v().getApplicationClasses()`.
    *   Write Annotation Parsers for Spring (`@RestController`, `@RequestMapping`) and Servlet (`@WebServlet`).
    *   Implement **Fat JAR Support**: Auto-extract `BOOT-INF/classes` and `BOOT-INF/lib` to temp workspace.
    *   Implement **Project Workspace**: Create `.jbytescanner` folder for isolated configs and results.
*   **Deliverable**: Running the tool generates `api.txt` containing a complete list of API routes found in the JARs.

## Phase 2.5: Component Fingerprinting (SCA) [PLANNED]
*   **Goal**: Identify versions of third-party libraries to enable version-aware taint analysis (pruning rules for safe versions).
*   **Tasks**:
    *   Implement `ComponentIdentifier`.
    *   Extract version info from `pom.properties`, `MANIFEST.MF`, or class signatures.
    *   Output results to `components.txt` in the workspace.

## Phase 3: Call Graph & Basic Data Flow (5 Days)
*   **Tasks**:
    *   Implement Soot `EntryPoints` selector (using routes from Phase 2).
    *   Configure `CallGraph` builder (Start with CHA for performance).
    *   Implement basic `ReachabilityAnalysis`: Determine if a Source can reach a Sink via the Call Graph.
*   **Deliverable**: Ability to detect simple method call chain vulnerabilities (e.g., Controller directly calling `exec`).

## Phase 4: Taint Analysis & Optimization (5-7 Days)
*   **Tasks**:
    *   Implement Taint Propagation (Soot `SmartLocalDefs` for intra-procedural + CallGraph for inter-procedural).
    *   **Memory Optimization**: Implement Exclusion Lists and Batch Analysis Mode.
    *   **SCA Integration**: Skip analysis if component version is safe (based on Phase 2.5).
    *   **Testing**: Benchmark against WebGoat JARs, monitoring memory peaks.
*   **Deliverable**: A functional Scanner capable of real vulnerability detection with controlled memory usage.

## Phase 5: Reporting & Delivery (2 Days)
*   **Tasks**:
    *   Implement `SarifReporter`: Convert Phase 4 results to JSON/SARIF.
    *   Write `README.md` and User Manual.
    *   Package as a single `JByteScanner.jar` (Maven Shade Plugin).

## Quick Start for Next Developer

1.  **Initialize**: Create Maven project in `D:\workspace\javaspace\JByteScanner`.
2.  **Dependencies**: Add `soot`, `snakeyaml`, `commons-cli`/`picocli`.
3.  **Guidance**:
    *   Strictly follow `DESIGN.md`.
    *   **Do not** reference the `woodpecker` source code.
    *   Use `D:\tools\opencode\test_jars` (create it) for testing with a sample SpringBoot JAR.
