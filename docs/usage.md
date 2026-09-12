# Usage

## One-call engagement

The entire audit runs server-side in a single tool call:

```
run_engagement(target="/path/to/source", scope="", mode="bug-bounty")
```

For a URL target, pass the scope:

```
run_engagement(target="https://target.com", scope="*.target.com", mode="bug-bounty")
```

Returns: scope enforcement result, blitz triage (files, hits, matched chains),
eagle-eye traced chains with tool manuals attached, findings (all marked
HYPOTHESIS until verified), and memory capture summary.

## Granular path (manual)

When you want finer control than the one-call path:

1. `blitz_scan(path)` — enumerate unauth entry points + dangerous sinks.
2. `eagle_eye(path, symbol)` — confirm a sink is in scope of a handler and
   unguarded.
3. `read_tool_manual(name)` — pull the exploit tool's full manual.
4. `strike_verify(...)` — live verification with a marker + negative control.

Only after `strike_verify` reflects your marker AND the chain's
`negative_control` stays inert do you have a finding.

## Engagement modes

| Mode | Behavior |
|---|---|
| `bug-bounty` | Strict scope: no-DoS, exclusion-aware, authorized-research guardrails. |
| `red-team` | Full active testing (with scope enforcement still applied). |
| `ctf` | Per-challenge targets. |

`scope_check` runs before active testing in every mode. Authorized targets only.

## Supporting layers

- `tool_lookup` / `ensure_tool` — find + auto-install a security tool.
- `skill_lookup` / `read_skill` — search 32 universal playbooks.
- `read_tool_manual` / `read_playbook` — 317 manuals + 17 playbooks.
- `detect_waf` / `tech_correlation` / `cve_correlation` / `port_correlation` —
  intelligence data layer lookups.
- `payload_lookup` / `template_lookup` — exploit payloads + nuclei templates.
- `remember` / `memory_lookup` / `memory_forget` — persist + recall + remove
  verified knowledge.
- `cvss_score` / `dedup_findings` / `generate_report` — self-computed CVSS,
  root-cause dedup, and reproducible reports.
- `run_enterprise_benchmark` / `coverage_matrix` — measure detection quality and coverage.

## Memory

`run_engagement` auto-captures matched escalation chains as `pattern` memory
entries (deduped). Use `remember` explicitly for reusable insights you want to
persist. Only `verified=true` entries are authoritative.

Memory lives at `~/.blitzstrike/memory.jsonl` (override with `BLITZSTRIKE_HOME`).
