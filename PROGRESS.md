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
- [x] Generate `api.txt`.

## Phase 3: Call Graph & Basic Data Flow [PENDING]
- [ ] Implement `CallGraphBuilder` (Start with CHA).
- [ ] Implement `EntryPoints` selector using `api.txt` or discovered routes.
- [ ] Implement basic `ReachabilityAnalysis` (Source -> Sink).
- [ ] Verify simple call chains.

## Phase 4: Taint Analysis & Optimization [PENDING]
...

## Phase 5: Reporting & Delivery [PENDING]
...
