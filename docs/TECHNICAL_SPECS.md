# JByteScanner Technical Optimization & Evolution Plan (Expert Edition)

## Overview
This document outlines the technical implementation strategies for the Red Team-focused evolution of JByteScanner, incorporating expert review feedback.

---

## Known False Negative: JDBC URL Flow Missed

### Reproduced Case
*   Target: Qiyuesuo setup endpoint `GET /setup/dbtest`.
*   Observed behavior: call graph builds successfully and the worklist processes thousands of tasks, but the final vulnerability count is `0`.
*   Confirmed reachable business flow:
    *   `com.qiyuesuo.setup.SetupController.dbtest(...)`
    *   `com.qiyuesuo.setup.SetupService.validateDatabase(...)`
    *   `com.qiyuesuo.setup.SetupService.dbtest(...)`
    *   `com.qiyuesuo.database.DatabaseService.getConnection(...)`
    *   `com.qiyuesuo.database.DefaultConnectionManager.getConnection()`
    *   `com.qiyuesuo.database.DatabaseConnection.getConnection(...)`
    *   `java.sql.DriverManager.getConnection(...)`

### Root Cause Breakdown
1.  **Sink modeling gap**
    *   Current rules cover SQL execution sinks such as `Statement.execute*` and `JdbcTemplate.execute/query`.
    *   Current rules do **not** cover JDBC connection-establishment sinks such as `DriverManager.getConnection(...)`.
    *   This causes JDBC URL injection / SSRF-style abuse to be invisible even if taint reaches the terminal API.
2.  **Receiver/object taint gap**
    *   `WorklistEngine` currently maps tainted call arguments to callee parameters only.
    *   It does not propagate taint from a tainted receiver into callee `this` for instance calls.
    *   As a result, flows of the form `source -> object field -> instance method -> sink` are truncated.
3.  **Incomplete summary system**
    *   `MethodSummary` defines `paramsToThis` and `thisToReturn` capabilities.
    *   `SummaryGenerator` and `WorklistEngine` do not yet fully generate/apply those facts.
    *   Return-value propagation is also incomplete, which drops factory/builder/helper chains.

### Design Implication
The current engine is strong enough for simple `source -> argument -> sink` flows, but it under-approximates real-world Java service code where taint frequently moves through:
*   constructors
*   object fields
*   instance receivers (`this`)
*   helper return values

---

## Phase 8: Tactical Intelligence Implementation

### 8.1 Secret Scanner (Tri-Layer Architecture)
*   **Layer 1: Static String Analysis**
    *   Iterate `Scene.v().getApplicationClasses()` -> Fields & Method Bodies (`ldc`).
    *   **Entropy Check**: Calculate Shannon Entropy for strings > 20 chars. High entropy (>4.5) suggests keys/tokens.
    *   **Pattern Match**: Regex for specific providers (AWS `AKIA...`, Private Key Headers).
*   **Layer 2: Config File Analysis**
    *   Class: `ConfigScanner`.
    *   Logic: Unzip JAR, scan `application.properties`, `application.yml`, `bootstrap.yml`.
    *   Keyword Search: `password`, `secret`, `key` (case-insensitive keys) + High Entropy Values.
*   **Layer 3: Encoded Secret Detection**
    *   Control Flow Analysis: Detect `Base64.getDecoder().decode(StringConstant)`.
    *   Decode statically and re-run entropy/pattern checks on the decoded value.

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
    *   Model attacker-controlled JDBC URL as a high-risk network/database sink.
    *   Support classification as SSRF, JDBC URL injection, or connection abuse depending on rule taxonomy.

### 8.5 Receiver/Object Propagation
*   **Engine target**: `com.jbytescanner.analysis.WorklistEngine`
*   **Required changes**:
    *   When the call site is an `InstanceInvokeExpr`, if the base object is tainted, seed callee `this` as tainted.
    *   Preserve taint across constructor initialization patterns such as `new Obj(tainted)` followed by instance calls.
    *   Track field-backed propagation for common flows where tainted parameters are stored into object state and later consumed.

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
    *   SHA-1 Hash.
    *   Maven `pom.properties` (GroupId/ArtifactId).
    *   **Class Signature**: Check for existence of specific classes/methods to identify shaded jars.
*   **Data Source**: Embedded `nvd_lite.json` or `known_vuln_libs.json`.

### 10.2 Interactive Audit Shell
*   **Technology**: JLine3.
*   **Features**:
    *   `search`: Regex search for methods.
    *   `path`: Shortest path query.
    *   `inspect`: Dump Jimple.
    *   `add-sink`: Runtime rule modification.
    *   `export`: Export CallGraph to `.dot` or Burp format.

### 10.3 Enhanced Reporting (Source Code Mapping)
*   **Problem**: Microservices (multiple JARs) cause SARIF path collisions.
*   **Solution**: JAR-Aware URI Prefixing.
    *   SARIF `uri` format: `{jarNameWithoutVersion}/{packagePath}/{ClassName}.java`.
    *   Example: `user-service/com/example/UserController.java`.
*   **Workflow**:
    1.  User decompiles JARs into folders matching the JAR name (e.g., `decompile/user-service/`).
    2.  JByteScanner generates SARIF with matching prefixes.
    3.  VSCode SARIF Viewer automatically resolves the correct file.
*   **Helper**: JByteScanner can output a `decompile.sh` script to automate the folder creation and CFR execution.
