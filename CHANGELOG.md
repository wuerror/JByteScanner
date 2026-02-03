# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Strict Dependency Isolation (Phase 6.3)**:
    - Refactored `JarLoader` to explicitly distinguish between "Target Jars" (matching `scan_packages`) and "Library Jars".
    - Target Jars are now loaded into Soot's `process_dir` (generating Jimple bodies), while Library Jars are loaded into `classpath` (signatures only).
    - This architecture prevents crashes and significantly improves stability when analyzing complex third-party libraries (e.g., `com.itextpdf`, `org.bouncycastle`).
    - Spring Boot `BOOT-INF/classes` is automatically treated as Target.

### Fixed
- **NPE in RuleManager**: Fixed `NullPointerException` when processing CallGraph edges where `target()` method is null during Backward Reachability Analysis.
- **DiscoveryEngine Compilation**: Fixed variable reference error (`appJars` -> `targetAppJars`).
