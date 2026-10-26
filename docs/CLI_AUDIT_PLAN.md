# CLI audit and missed-flow diagnosis (planned)

## Purpose

Make JByteScanner usable as a command-line analysis tool for a human auditor or a local AI agent. A missing SARIF result is not proof that a flow is impossible. Diagnosis must expose the stage at which evidence stops and distinguish `no` from `unknown`.

The CLI is the integration boundary. No MCP server is planned. Commands must have accurate `--help`, machine-readable JSON on stdout, diagnostics and logs on stderr, and documented exit codes. Existing `-m scan` and `-m api` usage remains compatible.

## Commands

The exact command spelling may be adjusted to fit Picocli without breaking existing invocations. The intended interface is:

```text
jbytescanner diagnose <deployment-package> --sink '<Tai-e method signature>' [--source '<Tai-e method signature>'] [--source-index N] --json
jbytescanner query <workspace> findings|finding|scan-status ... --json
```

`diagnose` runs a targeted analysis. `query` reads existing scan artifacts without starting Tai-e. The sink signature is required and must include owner, return type, method name, and parameter types. A source selector narrows the diagnosis; without it, the result covers all configured sources that could be observed.

Ordinary scanning keeps its current outputs and behavior. It does not collect or write a new diagnostic record by default. A targeted `diagnose` invocation writes only bounded, target-specific evidence under the workspace. `query` may reuse existing `worker-result.json`, expansion metrics, and finding sidecars; if they lack the needed evidence, it returns `unknown` and indicates that targeted diagnosis is required.

## Diagnostic stages

Each stage returns `yes`, `no`, or `unknown`, with an evidence reference and a short explanation:

1. The exact target invoke exists in application or dependency application bytecode, with its caller and artifact role. This check must use owner, name, and descriptor; an owner/name-only pre-scan is insufficient for an exact conclusion.
2. The sink rule and sensitive index are configured and emitted into Tai-e configuration. The source is present in the current `api.txt` or explicit rules, with the chosen parameter index.
3. The selected entry method resolves to a body and is injected. Record unresolved, phantom, abstract, native, and skipped cases separately.
4. The target caller and invoke are reachable, and relevant call edges are resolved where this can be observed. A bytecode invoke by itself does not prove reachability.
5. A raw Tai-e flow matches the selected source and sink. If it does, report whether FindingPipeline placed it in main, low-confidence, or suppressed output, including reason codes.
6. If the preceding checks pass but no flow is captured, collect bounded local IR, call-edge, and taint facts for the selected target. Report the last proven taint location and candidate unmodeled transfer only when supported by those facts. If Tai-e's available API cannot identify the propagation frontier, use `unknown`.

The result must not present endpoint-only source/container/sink display text as a proven hop-by-hop path. A failed, timed-out, or incomplete worker leaves dependent stages `unknown`.

## JSON contract and worker status

Use a versioned schema with a target selector, scan input counts, worker status, stage results, matched flow/finding identifiers, evidence references, limits reached, and suggested next checks. Evidence references should point to stable method signatures, invoke locations, rule identities, and artifact paths. Include an explicit evidence level so consumers can distinguish bytecode facts, reachability facts, taint results, and inferences.

`query scan-status` reports the actual status from `worker-result.json` (`SUCCESS`, `FAILED`, `OOM`, `TIMEOUT`, `CANCELLED`). It does not compute deployment/config content fingerprints and does not gate results on artifact freshness. Finding queries read existing sidecars directly and do not perform a freshness check. Do not serialize the Tai-e World, a full heap, or an unbounded global graph as a diagnostic record. Put size, depth, and time limits on target-specific evidence collection, and report truncation in JSON.

## Delivery order and acceptance

1. Define the JSON schema, evidence states, scan input/worker status fields, CLI help, and exit codes. Reuse existing worker and finding fields where possible.
2. Implement deterministic checks for invocation, rules, entry injection, reachability, raw flows, and report disposition.
3. Add bounded Worker-side propagation evidence. Confirm which conclusions Tai-e 0.5.4 can actually support before claiming a precise break point.
4. Add offline `query` commands for scan status, findings, and complete source instances.
5. Test positive and negative cases for missing entry, signature/index mismatch, unreachable invoke, missing transfer, suppressed flow, worker success/failure, and missing worker artifacts. Measure the added time, memory, and artifact size of targeted diagnosis; ordinary scan cost should remain unchanged.

Known missed-flow examples should identify a supported failure stage or explicitly return `unknown`. Zero findings must never be translated into a claim that no vulnerability exists.

## Implemented interface (v1)

The CLI uses the following spelling. JSON is the default output for both commands; `--json` is accepted for compatibility. Logs and errors are routed to stderr for `diagnose` and `query` only. Ordinary `-m scan` and `-m api` behavior and outputs are unchanged.

```text
JByteScanner diagnose <deployment-package> --sink '<Tai-e signature>' \
  [--sink-index N|base|result] [--source '<Tai-e signature>'] \
  [--source-index N|base|result] [--max-callers N] [--max-target-invokes N] \
  [--worker|--no-worker] [--max-heap-mb N] [--timeout-minutes N] [--json]

JByteScanner query <workspace> [findings|finding|scan-status] \
  [--sink '<Tai-e signature>'] [--sink-index N|base|result] \
  [--source '<Tai-e signature>'] [--source-index N|base|result] \
  [--limit N] [--json]
```

* `query finding` requires `--sink`. `query findings` accepts optional exact filters.
* `<workspace>` may be the project directory or the `.jbytescanner` directory itself.
* A sink/source signature must include owner, return type, method name, and the complete parameter list. Matching is by exact owner/return/name/parameter identity, so overloads are never conflated. The optional index filter is matched exactly (`0`, `base`, `result`, ...).
* Targeted records are written under `<workspace>/diagnosis/<batchId>/diagnosis.json` and `<workspace>/diagnosis/latest.json`; targeted worker files stay in the same batch directory.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Diagnosis/query executed and JSON was emitted (stages may still be `unknown`). |
| 2 | Invalid CLI usage or malformed Tai-e signature. |
| 3 | Input/workspace/artifact read error. |
| 4 | Tai-e worker failed, OOM, timed out, or otherwise did not complete. |
| 6 | `query` requested evidence that is absent; run targeted `diagnose`. |

### JSON schemas

* `schemaVersion: jbs-diagnosis/v1` (`diagnose`). Stage IDs are `invocation`, `rule`, `source`, `entry`, `reachability`, `raw_flow`, `finding_disposition`, and `propagation_frontier`. Each stage carries `state` (`yes`/`no`/`unknown`), `summary`, `evidenceLevel`, stable evidence references, and `details`. `scanIdentity` now carries only necessary input/evidence context: `artifactCount`, `targetAppJarCount`, `classPathJarCount`, `taintConfigPath`, and `workerResultPath`.
* `schemaVersion: jbs-query/v1` (`query`). Finding queries return complete `CanonicalFinding` records (including instances) when sidecars exist. Query output has no `artifactFreshness` or fingerprint fields.
* `zeroFindingsDoesNotProveAbsence` is always true. A `raw_flow: no` result is reported as `not_observed_not_proven_absent`, never as proof of safety.

### Evidence and limitations

* `invocation` is an exact ASM owner+name+descriptor check over target and dependency application artifacts. It proves a bytecode call site only.
* `rule` and `source` are verified against the actual generated `taint-config.yml` (or shard directory), including the emitted sensitive index.
* `entry` and `reachability` use the Worker's Tai-e World and PTA call graph. Entry status distinguishes unresolved, phantom, abstract, native, duplicate, and injected cases. Worker failure or truncation leaves dependent stages `unknown`.
* `raw_flow` matches only the exact configured sink signature/index and the selected source signature/index.
* `finding_disposition` replays the same `FindingPipeline` and reports `main`, `low_confidence`, or `suppressed` with reason codes.
* `propagation_frontier` is `unknown` when no flow is captured. Tai-e 0.5.4 exposes completed endpoint taint flows, not intermediate taint facts, so JByteScanner reports `lastProvenTaintLocation: null` and `candidateUnmodeledTransfer: null` instead of inventing a break point. Bounded invoke/call-edge/IR facts and all truncation limits are included in `details`/`limits`.
* Targeted worker evidence is bounded by `--max-callers`, `--max-target-invokes`, worker reachable-method/application-method caps, and per-invoke callee caps. Truncation is reported in JSON. No World, heap, or unbounded global graph is serialized.
* Ordinary scans do not set the diagnostic request and therefore collect no extra target evidence.

### Worker status and scan inputs

* `query scan-status` reads `worker/single/worker-result.json` and reports `status`, `exitCode`, `worldCompleted`, `analysisCompleted`, timing, and taint-flow count. A successful worker returns `0`; a failed/OOM/timeout/cancelled worker returns `4`; a missing or unreadable worker result returns `6`.
* `query findings` and `query finding` read `findings-main.jsonl`, `low-confidence.jsonl`, and `results-suppressed.jsonl` directly. Existing records are returned even if `worker-result.json` is missing or records a failed worker; worker status is included in `notes`/`worker` when available, but does not gate the query and never turns a finding into an absence claim.
* No deployment or config content hashing is performed. Temporary extraction paths and missing fingerprints therefore cannot downgrade evidence or change the exit code.
* Necessary scan input/evidence paths remain visible: `target.path` and `target.workspace` in diagnosis, `scanIdentity.*Count`/`taintConfigPath`/`workerResultPath`, the `artifacts` list, and `worker.requestPath`/`worker.resultPath` in `scan-status`.
* Targeted worker evidence is bounded by `--max-callers`, `--max-target-invokes`, worker reachable-method/application-method caps, and per-invoke callee caps. Truncation is reported in JSON. No World, heap, or unbounded global graph is serialized.
* Ordinary scans do not set the diagnostic request and therefore collect no extra target evidence.
