# JByteScanner Development Roadmap

This document tracks the evolution of JByteScanner into a specialized Red Team tool.

## ✅ Completed Phases (Core Engine)

### Phase 1-5: Foundation & Basics
- [x] **Skeleton**: Project structure, ConfigManager, CLI.
- [x] **Asset Discovery**: Spring Boot/Servlet API extraction.
- [x] **Analysis Engine**: Soot integration, CHA CallGraph, Basic Taint Analysis.
- [x] **Reporting**: SARIF output generation.

### Phase 6: Stability & Performance
- [x] **Structured State**: `AnalysisState` for efficient memoization.
- [x] **Pruning**: Backward Reachability Analysis to remove dead paths.
- [x] **Isolation**: Strict separation of Target Jars vs Library Jars (Ghost Classes).

### Phase 7: Advanced Analysis
- [x] **Worklist Engine**: Iterative fixed-point algorithm to prevent StackOverflow.
- [x] **Leaf Optimization**: Method Summaries for leaf nodes.

---

## 🚀 Active Phase: Tactical Intelligence (Phase 8)

**Goal**: Deliver immediate high-value findings suitable for penetration testing.

### Phase 8.1: Secret Scanner (Tri-Layer) [COMPLETED]
- [x] **Static String Scan**: Regex + Entropy check on Constant Pool.
- [x] **Config Scan**: Parse `application.properties/yml` inside JARs.
- [x] **Encoded Scan**: Detect and decode Base64 strings.

### Phase 8.2: Vulnerability Scorer [COMPLETED]
- [x] **R-S-A-C Model**: Implemented Reachability * Severity * Auth * Confidence scoring.
- [x] **Auth Detector**: Heuristic detection of `@PreAuthorize`, `@Secured`, and custom auth annotations.
- [x] **Rule Enhancement**: Added `severity` and `category` (code-exec, sqli, etc.) to rules.yaml.
- [x] **Report Upgrade**: SARIF report now includes Risk Level and numerical Score.

## 🔮 Future Phase: Interactive Triage (Phase 9)
- [ ] **Scoring Engine**: Implement 5-dimension scoring model (Sink, Reachability, Flow, Auth, CVE).
- [ ] **Report Integration**: Add scores to SARIF/Markdown output.

### Phase 8.3: Smart PoC Generator [COMPLETED]
- [x] **Burp Request Gen**: Generate raw HTTP requests.
- [x] **Smart Payloads**: Context-aware placeholders (JSON vs Form).

### Current Known Gaps
- [ ] **False Negative: JDBC URL / Connection Sinks**:
  - Case study: `GET /setup/dbtest` in the Qiyuesuo target is reachable from `com.qiyuesuo.setup.SetupController.dbtest(...)` to `java.sql.DriverManager.getConnection(...)`, but the engine reports 0 findings.
  - Root cause 1: `default_rules.yaml` models SQL execution sinks such as `Statement.execute*` and `JdbcTemplate.execute/query`, but does not model JDBC connection-establishment sinks such as `DriverManager.getConnection(...)` or URL-setting APIs on common `DataSource` implementations.
  - Root cause 2: the current worklist engine only propagates taint through callee parameters and does not propagate taint into instance receivers (`this`), constructors, object fields, or return values, so flows like `param -> field -> this.method() -> sink` are dropped.
  - Root cause 3: method summaries define placeholders for `paramsToThis` and `thisToReturn`, but the summary generator and worklist engine do not yet produce and consume these facts.

### Planned Fix Plan
- [ ] **8.4 Sink Coverage Expansion**:
  - Add JDBC URL / connection sinks to `default_rules.yaml`, starting with `java.sql.DriverManager.getConnection(...)` and common `DataSource` URL setters.
  - Revisit sink taxonomy so JDBC URL control can be scored as SSRF / JDBC URL injection / connection abuse instead of being limited to SQL execution only.
- [ ] **8.5 Receiver/Object Taint Propagation**:
  - Extend `WorklistEngine.scheduleCallee()` to propagate tainted instance receivers into callee `this` for `InstanceInvokeExpr`.
  - Add constructor and field-backed object flow support for chains like `source -> new Obj(tainted) -> this.field -> sink`.
- [ ] **8.6 Summary Completion**:
  - Implement `param -> this`, `this -> return`, and return-value propagation in `SummaryGenerator` and `WorklistEngine`.
  - Upgrade memoization state to capture object/receiver taint facts in addition to tainted parameter indices.

---

## 🔮 Future Phases

### Phase 9: Deep Exploitation Chains
- [ ] **9.1 Auth Bypass**: Advanced Spring Security config analysis.
- [x] **9.2 Gadget Suggest**: Dependency check and suggest known gadget (from java-chains).
- [ ] **9.3 Gadget Mining**: Two-stage deserialization chain discovery.

### Phase 10: Interactive & SCA
- [ ] **10.1 Offensive SCA**: Fingerprint libraries & link to CVEs.
- [ ] **10.2 Interactive Shell**: REPL for manual graph querying.
- [ ] **10.3 Enhanced Reporting**: Source Code Mapping & Decompile Helpers.

### Phase 11: Performance
- [ ] Engine Hardening (Timeouts).
- [ ] Incremental Analysis.
