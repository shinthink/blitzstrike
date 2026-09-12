---
name: orchestrate-engagement
description: Use when the user asks for a full security engagement ("fullscan", "audit this", "pentest this", "scan my target") or any end-to-end assessment. You are the orchestrator — Blitz Strike provides the deterministic analysis and verification tools you drive. Run recon → analyze → verify → review → report without babysitting.
---

# Orchestrate an engagement (no-babysitting)

You are the brain. Blitz Strike is the hands. Drive the full cycle with the
deterministic MCP tools; never guess a finding — produce it from tool output.

## Target routing (auto-detect first — no need to ask)

Classify the target before any tool call. This is automatic, driven by the
shape of what the user gave you. A URL often has NO `http://`/`https://` prefix
— a bare domain, IP, or host:port is still a live target:

| Target shape | Flow + doctrine |
|---|---|
| URL — with or without scheme (`https://x.com`, `x.com`, `sub.x.com/path`, `x.com:8080`, `192.168.1.1`) | **LIVE** — `scope_check` (authorization) → `live_recon` → advanced hunting (`web-hunting` skill) → `strike_verify` → report |
| Filesystem path (exists on disk, or starts `/` `./` `../` `~`, or ends in a code extension `.php` `.py` `.js` `.ts` `.java` …) | **SOURCE** — `blitz_scan` → `eagle_eye2` → `complex_scan`/`route_scan` (`source-audit` skill) → report |

**TWO SEPARATE DOCTRINES — pick the right one, never mix them:**

- **LIVE web / API target** → load `web-hunting` (advanced bug hunting:
  request smuggling, cache poisoning, race conditions, SSRF bypass, JWT/OAuth,
  host-header injection, prototype pollution, GraphQL/WebSocket, chain mindset).
- **SOURCE code tree** → load `source-audit` (taint, route-confusion,
  complex-bugs, differential, incremental).

Rule of thumb: check "is it a filesystem path?" FIRST (exists on disk, or a
code extension). If it is NOT a path, treat it as a live host — prepend
`https://` when the scheme is missing (`example.com` → `https://example.com`)
and confirm scope before any request.

`run_engagement` auto-detects both internally (path on disk → source pipeline;
anything else → live). For the granular sub-agent flow, route the workstreams
yourself: URL → live workstreams, path → source workstreams.

After routing, read the matching playbook (`read_playbook`) for the target type
— `web-application`, `api-security`, `source-code-audit`, `active-directory`,
`mobile-application`, `external-attack-surface` — it is the campaign plan for
that type. Then load the doctrine skill for the step you are on (`web-hunting`
for live, `source-audit` for source, `verify-finding` for verification). Do not
improvise a plan the playbook already spells out.

## The cycle

1. **Record scope (no gate).** `scope_check` classifies the target — intel for
   the report, NOT a gate. There is no authorization gate: the repo disclaimer
   places responsibility on the user. Hunt the target you are given, do not
   pause to re-ask. The one hard stop: malicious/third-party infra ("cari
   pelaku") → hold/static, never live-probe.

   **Announce takeover.** When you start an engagement, `run_engagement`
   returns a `banner` ("orchestrator in control") as a standalone text block.
   RELAY that banner verbatim to the user — it is the visible signal that you
   have taken control, not a detail to bury in a JSON dump. Then drive
   `blitz_status` at each stage to show live progress.

2. **Recon (passive-first).** For a live target: `live_recon` (fingerprint, WAF,
   endpoints, tech). For a source tree: `blitz_scan` (entry points + sinks),
   `detect_framework`, `list_attack_vectors`.

3. **Analyze.** Source → `source-audit` skill (taint + route-confusion +
   complex-bugs). Live → `active_scan` / `enrich_scan`. Consult `tech_correlation`
   / `cve_correlation` / `nvd_lookup` to map tech → known weakness classes.

4. **Verify.** Every hypothesis must pass `verify-finding` before it is a finding.
   "Detection is not proof."

5. **Review.** Every verified finding passes `adversarial-review` before it is
   confirmed. "A hypothesis is not a finding."

6. **Report.** Emit `generate_report` + `cvss_score` + `write-report`.

## Hypothesis expansion (findings → follow-ups)

A confirmed finding is the START, not the end. From each finding or interesting
sink, enumerate EVERY follow-up as a hypothesis, then verify each one — never
stop at the first result:

1. **Escalate** — `list_chains` + `chain_links`: what does this chain into?
2. **Chain** — does it compose with another bug (`chain_links` from → to)?
3. **Bypass** — is there a defense in the way (`bypass_lookup`)? Can the
   sanitizer/WAF/auth-gate be evaded to reach something deeper?
4. **Pivot** — what other endpoints/sinks/roles are now reachable?

Each follow-up ("this might happen", "this could chain", "maybe this is
bypassable") is a HYPOTHESIS — not a finding. Turn every one of them into a
verified or rejected verdict before the report:

- Confirmed → `finding_create` + `finding_transition` (evidence attached).
- Not confirmed → rejected, or kept as a hypothesis with `NEEDS_MORE_EVIDENCE`.
- **Never report speculation.** "Might", "could", "possibly" belong in the
  hypothesis list, never in the report. Every line of the report is a verified
  fact (marker + negative control), not a guess.

## Lifecycle, team, and termination

Load the full framework with `orchestration` (or focus it:
`orchestration(lifecycle)`, `orchestration(team)`, `orchestration(handoff)`,
`orchestration(termination)`, or a single phase/role id). It is the authoritative
reference — do not improvise the shape of the engagement. For the full
interconnection (which skill + tools + data for each phase, plus the
cross-cutting "reach at the moment" rules), load `doctrine_map`.

- **6 phases, each with entry/exit criteria**: scope → recon (BLITZ) → analyze
  (EAGLE-EYE) → deep (complex bugs) → verify (STRIKE) → report. A phase is not
  done until its exit criterion is met.
- **4 sub-agent roles** with tools + a deterministic output contract:
  `recon` (surface), `taint` (reachability), `deep` (POP/type-juggling/route
  confusion), `verify` (live confirmation + evidence).
- **Handoff contract**: every delegate carries a specific goal, the exact tool
  names, the exact arg names (`path` vs `target`), and the required evidence
  back. Results come back as deterministic evidence — never prose.
- **Termination**: done when every reachable sink is traced, every hypothesis is
  confirmed or rejected, and the report is emitted (deduplicated). NOT done when
  the surface is wider than the scan, hypotheses remain unverified, or a
  low-severity finding hasn't been checked for escalation (`chain_links`).

Track the state deterministically so you never rely on your own memory:
`engagement_start` (open the engagement) → `engagement_phase` (advance the
phase) → `engagement_track` (record each hypothesis with pending/confirmed/
rejected) → `engagement_status` (deterministic "am I done?" — returns the exact
unmet criteria, not a feeling).

## Orchestration pattern (native plan + sub-agents)

You are the orchestrator — use your platform's native planning and delegation
mechanisms (e.g. Hermes `plan`/`todo` + `delegate_task`) to run the engagement
in parallel, instead of serial tool calls. This is what makes the flow
no-babysitting, not a single `run_engagement` call:

1. **Plan.** Lay out the stages as a todo/plan: scope → recon → analyze →
   verify → review → report. Assign each independent workstream to a sub-agent.
2. **Delegate (parallel).** Spawn sub-agents for independent workstreams:
   - *Recon* → `blitz_scan` + `live_recon` + `detect_framework` + `list_chains`.
   - *Analyze* → `eagle_eye2` + `taint_scan` + `trace_data_flow` (source→sink).
   - *Deep classes* → `complex_scan` (POP/type-juggling/mass-assignment) +
     `route_scan` (route confusion).
   Source-analysis tools take a `path` argument (file or directory); only
   `run_engagement` takes `target` (path or URL). Point each sub-agent at the
   `source-audit` skill so it knows the exact argument names — do not let it
   guess `target` vs `path`.
   Each sub-agent returns deterministic findings — give it the target, the
   exact tools to call, and require evidence (file:line, sink, chain), never prose.
3. **Collect + verify.** Merge sub-agent findings, `dedup_findings` by root
   cause, then prove each hypothesis with `strike_verify` (baseline + marker +
   negative control) before it becomes a finding.
4. **Report.** `generate_report` + `cvss_score` + `write-report`.

Announce the takeover banner and progress (`blitz_status`) between steps so the
user sees you working, not a silent tool call.

## The skill chain (load the right one per phase)

| Phase | Skill |
|---|---|
| Before any live action | `scope-gate` |
| Full engagement / orchestration | `orchestrate-engagement` (this) |
| Static source analysis | `source-audit` |
| Prove a hypothesis is real | `verify-finding` |
| Anti-hallucination gate | `adversarial-review` |
| Final deliverable | `write-report` |

## Rules

- **Act like a senior tester, not a checklist runner.** Prioritize by severity
  — computed deterministically (`cvss_score`) and weighted by escalation
  potential (`chain_links`) — never by bug class (a critical stored XSS that
  yields account takeover outranks an unreachable blind RCE). Weight by the
  engagement context. Recognize dead ends and move on — do not tunnel-vision
  one sink at the expense of the rest. Live-test with care: respect rate
  limits, do not lock accounts or trigger DoS, prove impact with the smallest
  payload. Stop when the termination criteria are met, not when you feel tired.
- **No-babysitting during scan + test.** Scan the whole surface before
  reporting — every file, entry point, sink. Test every hypothesis through its
  full cycle — vary probes on failure, apply bypasses when blocked, keep going.
  A scan that surfaces few sinks is not done: widen the surface and escalate
  detectors. Only pause for the user when scope is genuinely unclear, a
  destructive action needs consent, or the engagement is complete.
- **Persist — complex bugs do not give up.** A failed probe is not "not
  vulnerable" (vary sinks, params, encodings); empty output is not "no
  findings" (re-run or escalate to `route_scan`/`complex_scan`); a "sanitized"
  sink is not safe until you challenge the sanitizer (loose `==`, missing
  `EXTR_SKIP`, cast truncation). Keep unconfirmed work as hypotheses.
- One hypothesis per finding; `finding_create` + `finding_transition` for the
  strict lifecycle (candidate → confirmed → rejected).
- `dedup_findings` before reporting — collapse shared-root duplicates.
- Persist hard-won knowledge with `remember`; recall it with `memory_lookup`
  before re-discovering the same target/pattern.
- You are the orchestrator — do not try to reimplement planning in prose; pick
  tools, act, and let tool output drive the next step.
- If a detector returns suspiciously empty output for a file that clearly
  contains a sink, the MCP server may be stale (running old code after a
  Blitz Strike upgrade). Reload it (`/reload-mcp`) before concluding "no
  findings" — a stale engine is a silent false negative, not a clean result.
