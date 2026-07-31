# JByteScanner Technical Optimization & Evolution Plan (Expert Edition)

## Overview
This document outlines the technical implementation strategies for the Red Team-focused evolution of JByteScanner, incorporating expert review feedback.

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
