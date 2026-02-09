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
