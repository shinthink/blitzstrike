# Findings & Evidence Engine

Blitz Strike follows one principle: **a scanner hit is a hypothesis; evidence is
the verdict.**

This document describes the canonical finding model, the strict lifecycle, and
the deterministic confidence engine. No other part of the codebase invents its
own finding shape — every producer funnels into these modules.

## Finding schema

`src/finding.ts` defines the single `Finding` model:

| Field | Meaning |
| :--- | :--- |
| `id` | Canonical id, `BS-YYYY-NNNNNN` |
| `status` | Lifecycle state (see below) |
| `title` | Human-readable title |
| `target` | `type` (web/api/source/mobile/network/other) + host/endpoint/path |
| `classification` | severity, CWE id/name/confidence, CVSS (evidence-based) |
| `confidence` | 0.0–1.0 deterministic score (NOT an AI opinion) |
| `confidence_level` | informational / suspected / likely / high_confidence / confirmed |
| `source` | attacker-controlled source (type + name + location) |
| `flow` | data-flow path (source → transforms → sink) |
| `sink` | security-sensitive operation (type + symbol + location) |
| `validation` | performed + baseline + negative_control |
| `evidence` | array of integrity-tagged evidence records |
| `chain` | escalation chain id/name |
| `impact` / `remediation` | impact + fix |
| `timestamps` | created / updated |

## Lifecycle

Strict, machine-readable state machine (`transition()` rejects illegal moves):

```
detected → triaged → hypothesis → validating → confirmed
                 ↘ rejected      ↘ false_positive
                 ↘ out_of_scope   ↘ blocked
                                  ↘ out_of_scope
```

`confirmed`, `false_positive`, `rejected`, `blocked`, `out_of_scope` are
terminal.

## Severity vs confidence

- **Severity** = impact (`critical` / `high` / `medium` / `low` / `informational`).
- **Confidence** = certainty (deterministic 0.0–1.0).

They are never combined. "Severity CRITICAL + confidence 0.41" = *potentially
critical, insufficient evidence*. "Severity MEDIUM + confidence 0.98" = *medium
impact, highly reliable*.

## Confidence engine

`computeConfidence()` is deterministic and weighted (configurable via
`setConfidenceWeights()`):

| Factor | Default weight |
| :--- | :--- |
| static_analysis | 0.20 |
| data_flow | 0.25 |
| reachability | 0.15 |
| preconditions | 0.10 |
| runtime_validation | 0.20 |
| negative_control | 0.10 |

Levels: `0.00–0.29` informational · `0.30–0.49` suspected · `0.50–0.69` likely ·
`0.70–0.89` high_confidence · `0.90–1.00` confirmed.

A high confidence score is **never** proof by itself — confirmation requires
validation + evidence.

## Evidence engine

`src/evidence.ts`:

- **Schema** — `evidence_id`, `type`, `description`, `source`, `sink`, `artifacts[]`, `recorded`, `provenance`.
- **Provenance (§16)** — every record carries chain-of-custody metadata: `tool`,
  `version`, `target`, `scope`, `parentEvidence`.
- **Integrity** — every artifact carries a SHA-256 (`sha256()`), verified by `verifyEvidence()`.
- **Secret redaction** — `redactSecrets()` strips passwords, API keys, tokens,
  cookies, `Authorization` headers, private keys before persistence/report/log/context.
- **Append-only** — confirmed evidence is never silently rewritten.

## Finding invariants (§53)

`src/invariants.ts` enforces hard, machine-checkable rules:

| Invariant | Enforcement |
| :--- | :--- |
| CONFIRMED requires evidence | `confirmFinding` throws without evidence |
| CONFIRMED requires clean negative control | `checkFindingInvariants` |
| CONFIRMED requires in-scope target | `checkFindingInvariants` |
| No raw secret in persisted evidence | `checkFindingInvariants` |
| Evidence hash must stay stable | `checkFindingInvariants` |

## Audit log (§45)

`src/audit.ts` emits structured append-only audit events to
`~/.blitzstrike/audit.jsonl`: `scope_checked`, `finding_created`,
`finding_updated`, `validation_finished`, `evidence_created`, … each carrying
timestamp, actor, tool, target, result, and correlationId.

## MCP tools

| Tool | Purpose |
| :--- | :--- |
| `finding_create` | create a canonical finding (default `detected`) |
| `finding_transition` | advance lifecycle (rejects illegal moves) |
| `confidence_score` | deterministic weighted confidence |
| `confidence_weights` | get/set the confidence weight factors |
| `redact` | redact secrets from arbitrary text |
| `finding_attach_evidence` | attach a redacted + hashed evidence record to a finding |
| `strike_resolve` | attach a live STRIKE verdict to a finding and advance its lifecycle |

`run_engagement` now emits canonical findings (status `hypothesis`, carrying
static + sink evidence) instead of ad-hoc `{chain_id, name, severity}` tuples.

## STRIKE verdict → lifecycle

`src/strike.ts` runs a baseline, a marker, and a negative-control request and
maps the result to a deterministic verdict that resolves a finding:

| Verdict | Condition | Lifecycle effect |
| :--- | :--- | :--- |
| `confirmed` | marker reflected, control inert | `hypothesis → validating → confirmed` (+ evidence, confidence 1.0) |
| `false_positive` | marker + control both reflected | terminal `false_positive` |
| `unconfirmed` | marker not reflected | stays `validating` (validation `unconfirmed`) |
| `blocked` | request failed/blocked | terminal `blocked` |

## Deduplication, CVSS & reports

- **Dedup** (`src/dedup.ts` + `dedup_findings`) — findings that share a root
  cause (`sink type × source type × CWE`) collapse into one group, so the same
  bug reached the same way in two files counts once.
- **CVSS** (`src/cvss.ts` + `cvss_score`) — a self-computed CVSS v3.1 base score
  + vector + severity (verified against known NVD values), instead of only
  reading a score from NVD.
- **Reports** (`src/report.ts` + `generate_report`) — deterministic markdown or
  JSON with a summary table and a SHA-256 integrity hash; same findings →
  byte-identical output.
