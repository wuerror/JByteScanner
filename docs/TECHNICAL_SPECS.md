# JByteScanner Technical Optimization & Evolution Plan (Expert Edition)

## Overview
This document outlines the technical implementation strategies for the Red Team-focused evolution of JByteScanner, incorporating expert review feedback.

---

## ~~Known False Negative: JDBC URL Flow Missed~~ → RESOLVED (v1.6.0)

### Reproduced Case
*   Target: a typical Spring Boot application with a database-test endpoint `GET /setup/dbtest`.
*   Original observed behavior: call graph builds successfully, worklist processes thousands of tasks, but final vulnerability count was `0`.
*   Confirmed reachable business flow:
    *   `com.example.setup.SetupController.dbtest(...)`
    *   `com.example.setup.SetupService.validateDatabase(...)`
    *   `com.example.setup.SetupService.dbtest(...)`
    *   `com.example.database.DatabaseService.getConnection(...)`
    *   `com.example.database.DefaultConnectionManager.getConnection()`
    *   `com.example.database.DatabaseConnection.getConnection(...)`
    *   `java.sql.DriverManager.getConnection(...)`

### Root Cause Breakdown & Resolution Status

1.  **Sink modeling gap** → **FIXED (Phase 8.4)**
    *   Added `java.sql.DriverManager.getConnection(...)` (all three overloads) as `JDBC_Driver_RCE` sinks in `default_rules.yaml`.
    *   `ConfigManager` now merges workspace-level `rules.yaml` with bundled defaults so user-customized configs do not lose default sink coverage.
    *   SSRF sink scope is intentionally focused on APIs that actually establish outbound access. `URL(String)` / `URI(String)` constructors are not treated as high-confidence SSRF sinks because they only materialize URL objects and create too many false positives.

2.  **Receiver/object taint gap** → **FIXED (Phase 8.5)**
    *   `WorklistEngine.scheduleCallee` and `InterproceduralTaintAnalysis`: tainted base objects are now mapped to callee `this` for all `InstanceInvokeExpr` calls.
    *   `IntraTaintAnalysis.flowThrough`: void instance method calls (`obj.setter(tainted)`) now taint the receiver `obj`, enabling subsequent field reads and method calls on `obj` to propagate taint correctly.
    *   `IntraTaintAnalysis.applyDefinition`: added `StaticFieldRef` read/write tracking via `taintedStaticFields: Set<SootField>`.
    *   `AnalysisState`: `thisTainted` flag added to memoization key — prevents a tainted-receiver entry from being deduplicated against an untainted-receiver entry for the same method.
    *   Receiver-based sink triggering remains enabled for categories where receiver state is a meaningful exploit signal, but is disabled for `sqli` so tainted `Statement` / `Connection` objects do not produce SQL injection false positives by themselves.

3.  **Incomplete summary system** → **Partially addressed; remaining gap (Phase 8.6)**
    *   Static method return values now propagate taint to the caller (`x = Utils.wrap(tainted)` → `x` tainted).
    *   Constructor arg → base taint is now handled intra-procedurally.
    *   `param → this → return` summaries (e.g., builder pattern across method boundaries) and full `thisToReturn` inter-procedural facts are not yet generated/consumed by `SummaryGenerator` + `WorklistEngine`. This remains the primary open gap.

### Remaining Open Gap (Phase 8.6)
The engine now correctly handles the most common Java taint patterns. The remaining gap is **cross-method field side-effects without receiver pre-tainting**:
```java
// Scenario: taint reaches this.field via a callee, but caller's local is not yet marked tainted
obj.setter(tainted);   // obj marked tainted in caller ✓ (Phase 8.5 fix)
String v = obj.field;  // obj tainted → v tainted ✓
sink(v);               // caught ✓

// Still incomplete: summary-driven param→this→return across multiple hops
Object result = factory.build(tainted);  // factory.build stores param to field, returns this
result.execute();                        // this.field reaches sink — needs summary facts
```

---

## Phase 8: Tactical Intelligence Implementation

### 8.1 Secret Scanner (Tri-Layer Architecture)
*   **Layer 1: Static String Analysis**
    *   ASM-based `AsmStringCollector` traverses class constant pools from `targetAppJars`.
    *   **Entropy Check**: Calculate Shannon Entropy for strings > 20 chars. High entropy (>4.6) suggests keys/tokens.
    *   **Pattern Match**: Regex for specific providers (AWS `AKIA...`, Private Key Headers).
*   **Layer 2: Config File Analysis**
    *   Class: `SecretScanner`.
    *   Logic: Scan `application.properties`, `application.yml`, `bootstrap.yml`, `.xml`, `.json` inside JARs.
    *   Keyword Search: `password`, `secret`, `key` (case-insensitive) + High Entropy Values.
*   **Layer 3: Encoded Secret Detection**
    *   Detect Base64 strings in constant pools, decode, and re-run entropy/pattern checks recursively.

### 8.2 Vulnerability Scorer (5-Dimensional)
*   **Class**: `com.jbytescanner.analysis.VulnerabilityScorer`
*   **Algorithm**: `Score = min(Base + Reachability + Flow + Auth + CVE, 100)`
    1.  **Sink Severity**: RCE(10), SQLi(8), SSRF(6).
    2.  **Reachability**: Public API (+30), Protected API (+10), Internal (0).
    3.  **Flow Complexity**: 
        *   Direct flow (hops <= 3) -> High Exploitability (+20).
        *   Deep flow (hops > 10) -> Low Exploitability (+0).
    4.  **Auth Barrier**: No Auth (+20), Weak Auth (+10), Strong Auth (0).
    5.  **CVE Bonus**: Matches known CVE pattern (+10).

### 8.3 Smart PoC Generator (Burp-Ready)
*   **Class**: `com.jbytescanner.report.PoCGenerator`
*   **Output**: Raw HTTP Request String (for Burp Repeater).
*   **Logic**:
    *   **Method/Path**: From `ApiRoute`.
    *   **Headers**: 
        *   Add `Host: target.com` placeholder.
        *   Add `Content-Type`: `application/json` or `application/x-www-form-urlencoded` based on annotation analysis.
    *   **Body Construction**:
        *   If `@RequestBody`: Generate JSON skeleton.
        *   If `@RequestParam`: Generate URL params or Form body.
        *   **Payload Injection**: Inject placeholder `{{PAYLOAD}}` into the tainted parameter.
*   **Example Output**:
    ```http
    POST /api/upload HTTP/1.1
    Host: target.com
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
    
    ------WebKitFormBoundary7MA4YWxkTrZu0gW
    Content-Disposition: form-data; name="file"; filename="payload.jsp"
    Content-Type: application/octet-stream
    
     {{SHELL_CODE}}
     ------WebKitFormBoundary7MA4YWxkTrZu0gW--
     ```

### 8.4 Sink Coverage Expansion
*   **Goal**: Close false negatives caused by terminal sink under-modeling.
*   **Planned additions**:
    *   `java.sql.DriverManager.getConnection(java.lang.String)`
    *   `java.sql.DriverManager.getConnection(java.lang.String,java.util.Properties)`
    *   `java.sql.DriverManager.getConnection(java.lang.String,java.lang.String,java.lang.String)`
    *   Common JDBC URL setter APIs on pooled `DataSource` implementations when present in classpath.
*   **Detection intent**:
    *   Model attacker-controlled JDBC URL as a high-risk `JDBC_Driver_RCE` sink and leave concrete exploitability validation to analyst review.
    *   Keep generic SSRF classification focused on ordinary outbound URL/HTTP access sinks.
*   **Current policy**:
    *   Treat generic outbound access APIs as SSRF sinks (`openConnection`, HTTP client `execute`, `openStream`).
    *   Treat JDBC connection establishment (`DriverManager.getConnection`) as `JDBC_Driver_RCE` rather than generic SSRF.
    *   Do not treat `new URL(String)` / `new URI(String)` as high-confidence SSRF sinks in the default rule set.

### 8.5 Receiver/Object Propagation ✅ COMPLETED (v1.6.0)
*   **Changes implemented**:
    *   `IntraTaintAnalysis.flowThrough`: All `InstanceInvokeExpr` void calls (`VirtualInvokeExpr`, `InterfaceInvokeExpr`, `SpecialInvokeExpr`) with a tainted argument now taint the receiver. This replaces the previous constructor-only handling and covers the common setter pattern.
    *   `IntraTaintAnalysis.applyDefinition`: Added `StaticFieldRef` handling — writes record the `SootField` in `taintedStaticFields: Set<SootField>`; reads check the set. The set is monotone (never killed) consistent with MAY-analysis.
    *   `WorklistEngine.checkSink` + `InterproceduralTaintAnalysis` sink block: Sink detection can fire on tainted receiver in addition to tainted arguments, covering `taintedObj.sinkMethod()` patterns for selected sink categories.
    *   `WorklistEngine.scheduleCallee` + `InterproceduralTaintAnalysis`: Tainted base object maps to callee `this` local.
    *   `AnalysisState`: `thisTainted` boolean included in `equals`/`hashCode` to prevent premature memoization deduplication.
*   **Covered chains**:
    *   `param → obj.setter(param)` → `obj` tainted → `obj.getter()` → tainted return → sink
    *   `new Obj(param)` → base tainted → `base.field` → sink
    *   `Cls.staticField = param` → `x = Cls.staticField` → sink
    *   `taintedObj.sinkMethod()` → sink for categories that allow receiver-based triggering

### 8.6 Summary Completion
*   **Classes**: `MethodSummary`, `SummaryGenerator`, `WorklistEngine`, `AnalysisState`
*   **Required changes**:
    *   Generate and consume `param -> this` facts.
    *   Generate and consume `this -> return` facts.
    *   Support return-value taint propagation in callers.
    *   Extend memoization beyond parameter bitsets so object/receiver taint does not collapse into false deduplication.

---

## Phase 9: Deep Exploitation Chains

### 9.1 Auth Bypass (Advanced)
*   **AntPathMatcher Simulation**: Reimplement Spring's path matching logic to correctly handle overlapping rules (`/api/**` vs `/api/public/**`).
*   **Hardcoded Credential Hunt**: Detect `if (var.equals("literal"))` patterns in Auth-related methods.

### 9.2 Deserialization Gadget Mining
*   **Strategy**: Two-Stage Analysis.
*   **Stage 1 (Feature Scan)**: Scan all classes for `Serializable` + `readObject`/`readResolve` + Dangerous calls inside them (Heuristic).
*   **Stage 2 (Deep Scan)**: Build *Local* CallGraph for candidate classes only.
*   **Knowledge Base**: Load `gadgets.yaml` for known library fingerprints (Commons-Collections, etc.).

---

## Phase 10: Interactive & SCA

### 10.1 Offensive SCA
*   **Multi-Fingerprint**:
    *   Maven `pom.properties` (GroupId/ArtifactId/Version).
    *   JAR filename parsing (name-version.jar pattern).
    *   MANIFEST.MF metadata.
*   **Data Source**: Embedded `gadgets.json` (400+ known gadgets from java-chains), matched against detected library versions.

### 10.2 Interactive Audit Shell (计划中)
*   **Technology**: JLine3.
*   **Features**:
    *   `search`: Regex search for methods.
    *   `path`: Shortest path query.
    *   `inspect`: IR inspection.
    *   `add-sink`: Runtime rule modification.
    *   `export`: Export call graph.

### 10.3 Enhanced Reporting
*   **Finding Pipeline (P0.6)**: Four-tier output — `raw-flows.jsonl`, `results-suppressed.jsonl`, `low-confidence.jsonl`, `result.sarif`.
*   **Sink Strength Classification**: Classifies sinks as CONSTRUCTOR, PARSER, INTERMEDIATE, or TERMINAL_SIDE_EFFECT with configurable suppression policies.
*   **Auth Scoring**: Worker-compatible auth detection using ASM-extracted route annotations; no dependency on host Tai-e World.
*   **PoC Generation**: Burp Suite-compatible HTTP requests with context-aware payload injection for discovered vulnerabilities.
