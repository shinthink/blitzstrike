# Blitz Strike — Autonomous Security Auditing (LLM-Driven)

Blitz Strike is a **universal security-audit toolbelt** that an LLM agent
(Hermes, Claude, OpenCode, Codex — any MCP client) drives end-to-end without
babysitting. The split is deliberate:

- **The LLM is the brain** — it plans, routes, reasons over results, delegates,
  and judges. It is never replaced by a deterministic loop.
- **Blitz Strike is the hands + knowledge + guardrails** — deterministic
  analysis, verification, the finding lifecycle, and the intelligence data
  layer.

## The three tiers

| Tier | What it does | Key tools |
|------|-------------|-----------|
| **BLITZ** | Attack-surface mapping, recon | `blitz_scan`, `blitz_file`, `live_recon`, `detect_framework`, `list_attack_vectors` |
| **EAGLE-EYE** | Source→sink reachability | `taint_file`, `eagle_eye2`, `trace_data_flow`, `route_scan`, `complex_scan` |
| **STRIKE** | Live validation | `strike_verify` (baseline + marker + negative control), `strike_resolve` |

Plus a canonical evidence-first finding engine (`finding_create` →
`finding_transition` → `finding_attach_evidence`) and a multi-language taint
engine (PHP/JS/TS/Python/Java).

## How autonomy actually works

The LLM drives a cycle, guided by three coordinated layers:

1. **Static `instructions`** — the mental model, target routing, resource map,
   and persistence doctrine, injected when the MCP server connects.
2. **Skills (doctrine)** — `bs-orchestrate-engagement`, `bs-scope-gate`,
   `bs-source-audit`, `bs-verify-finding`, `bs-adversarial-review`,
   `bs-write-report`, loaded per phase.
3. **Dynamic `next_steps`** — per-result guidance telling the LLM what to do
   after each tool call.

A full engagement is orchestrated with the platform's **native plan +
sub-agent** primitives (e.g. Hermes `plan`/`todo` + `delegate_task`): route the
target (URL vs source), read the matching playbook, then fan out recon /
analyze / deep-classes workstreams in parallel, collect, verify, and report.

## Guardrails (the anti-hallucination core)

- **Detection is not proof.** A scan hit is a hypothesis.
- **A hypothesis is not a finding.** Separate states, never conflated.
- **AI reasoning is not evidence.** Every finding carries deterministic evidence
  (marker reflection, negative control, source→sink trace, SHA-256-tagged).
- **Scope first.** Out-of-scope or destructive work is refused.

## The resource map (know what to reach for)

- **TOOL** = acts (scan, taint, verify, record).
- **PLAYBOOK** (17) = campaign plan for a target type (`web-application`,
  `api-security`, `source-code-audit`, `active-directory`, …).
- **SKILL** (38) = phase/technique doctrine.
- **MANUAL** (317) = deep reference for one tool.
- **PAYLOAD** (66 categories) = attack payloads for a class.
- **INTELLIGENCE** = 36 escalation chains, 18 chain→chain links, 34 attack-vector
  categories, bypass techniques, WAF/tech/CVE/port correlations.
