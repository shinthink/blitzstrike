---
name: source-audit
description: Use when auditing source code (PHP/JS/Python/Java/etc.) for vulnerabilities — static source→sink taint, route confusion/dispatch abuse, deserialization, type juggling, and mass assignment. This is Blitz Strike's deterministic static-analysis moat, distinct from live/dynamic testing.
---

# Source audit (deterministic static analysis)

Drive Blitz Strike's static analyzers over a source tree and turn each hit into a
hypothesis. Do not hand-guess; let the tools produce the source→sink evidence.

## Tool argument convention (read this first)

- **All source-analysis tools take `path`** (a file or directory):
  `blitz_scan`, `eagle_eye2`, `taint_scan`, `taint_file`, `blitz_file`,
  `trace_data_flow`, `eagle_grep`, `variant_analysis`, `enrich_scan`,
  `route_scan`, `complex_scan`, `detect_framework`.
  Example: `blitz_scan {path: "/repo/app"}`.
- **Only `run_engagement` takes `target`** (accepts either a source path OR a
  live URL). Do not pass `target` to the source-analysis tools — it is ignored.

## Workflow

1. **Map the tree.** `blitz_scan {path}` — entry points (nopriv hooks, REST
   routes, controllers) + sink inventory per file. `detect_framework {path}` per
   file to know what conventions apply.

2. **Trace data flow.** For each source→sink candidate:
   - `taint_file {path}` / `taint_scan {path}` — variable-level taint tracking.
   - `eagle_eye2 {path}` — whole-program interprocedural taint (PHP, method-aware).
   - `trace_data_flow {path}` — classify sources vs sinks across a file.
   - `variant_analysis` — group data-flow candidates by shared root cause.

3. **Escalate.** `enrich_scan {path}` — match detected sinks to escalation
   chains (SQLi → RCE, upload → shell, LFI → RCE). `list_chains` to see the full
   escalation taxonomy. `tech_correlation` for framework-specific weaknesses.

4. **Deep/complex classes.** Beyond plain taint, drive the dedicated detectors:
   - `route_scan {path}` — route confusion / dispatch abuse (`call_user_func`,
     `$obj->$method()`, batch/proxy forwarding, dynamic include, route match
     without path normalization).
   - `complex_scan {path}` — deserialization→POP chain (`unserialize` +
     `__destruct`/`__wakeup`/`__toString`), type juggling (loose `==`/`!=` vs
     hash/secret), mass assignment (`extract()`/`parse_str()` without a safe flag).

5. **Correlate.** `cve_correlation` + `nvd_lookup` for the framework/pattern to
   confirm the weakness class is real and known.

## Pitfalls

- A sink is not a finding — a sink **reached by attacker-controlled input** is a
  hypothesis. Check the source provenance before reporting.
- Framework accessors are sources too (`$request->input()`, `request.GET`,
  `@RequestParam`), not just `$_GET`.
- Parameterized queries, integer casts (`intval`/`absint`/`(int)`), and ORM calls
  are neutralizers — do not flag a sink that is actually sanitized.

## Output

Every confirmed sink → `finding_create` with the source→sink chain as evidence,
then `finding_transition` candidate → validated after `verify-finding`.
