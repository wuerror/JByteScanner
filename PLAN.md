# Development Plan (Red Team Edition - Expert Revised)

This plan focuses on evolving JByteScanner into a specialized tool for **Red Teams and Penetration Testers**, prioritizing exploitability, low noise, and tactical intelligence. It incorporates expert feedback to avoid common engineering pitfalls.

## Phase 1-7 [COMPLETED]
*   **Foundation**: Skeleton, Config, Asset Discovery, Call Graph (CHA), Taint Analysis.
*   **Optimization**: 
    *   **Phase 6**: Structured AnalysisState, Backward Reachability Pruning, Strict Dependency Isolation (Target vs Libs).
    *   **Phase 7**: Method Summaries, Worklist Engine (Iterative), Leaf Optimization.

---

## Phase 8: Tactical Intelligence & Scoring (MVP) [NEXT]
*   **Goal**: Deliver immediate high-value findings with low engineering risk.
*   **Tasks**:
    *   **8.1 Secret Scanner (Tri-Layer)**:
        *   Layer 1: Static High-Entropy String Scan (Constant Pool).
        *   Layer 2: Config File Scan (`application.properties/yml`).
        *   Layer 3: Encoded Secret Detection (Base64).
    *   **8.2 Vulnerability Scorer (5-Dim)**:
        *   Sink Type, Reachability (Public/Private), Filter Presence.
        *   **New**: Flow Complexity (Hop Count), CVE Correlation.
    *   **8.3 Smart PoC Generator (Burp-Ready)**:
        *   Generate **Raw HTTP Request** strings optimized for Burp Suite (Repeater/Intruder).
        *   Handle Content-Type (JSON/Form/Multipart) intelligently based on parameter types.

## Phase 9: Deep Exploitation Chains (Expert Mode)
*   **Goal**: Uncover complex vulnerabilities requiring logic analysis.
*   **Tasks**:
    *   **9.1 Auth Bypass Detection (Advanced)**:
        *   Simulate Spring Security `AntPathMatcher` logic (LIFO rules).
        *   Correlate Config vs Controller Annotations.
        *   Detect Hardcoded Credentials in logic (`if password == "admin"`).
    *   **9.2 Deserialization Gadget Mining (Two-Stage)**:
        *   Stage 1: Lightweight Feature Scan (Serializable + Magic Methods).
        *   Stage 2: Targeted Deep Analysis (Local CG) for candidates.
        *   Knowledge Base: `gadgets.yaml`.

## Phase 10: Interactive Audit & Offensive SCA
*   **Goal**: Empower expert review.
*   **Tasks**:
    *   **10.1 Offensive SCA (Multi-Fingerprint)**: 
        *   Match JARs via SHA1, Maven Coordinates, and Class Signatures.
        *   Link to NVD/CVE Data.
    *   **10.2 Interactive Audit Shell**: 
        *   JLine-based REPL.
        *   Commands: `search`, `path`, `inspect`, `add-sink`, `export-cg`.

---

## Phase 11: Performance & Stability
*   **Engine Hardening**: Timeout control for CallGraph construction, Memory management (Scene reset).
*   **Incremental Scan**: Diff-based analysis for CI scenarios.
