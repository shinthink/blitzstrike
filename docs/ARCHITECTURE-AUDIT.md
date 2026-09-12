# Architecture Audit — Mission Control → LLM-Driven Toolbelt

Step 1 of the LLM-driven refactor. Every Mission Control component is
classified into one of:

- **TOOL** — a deterministic check the LLM calls via MCP (produces a result the
  LLM reasons over).
- **SKILL** — "how to run the pentest" doctrine/knowledge the LLM loads
  (becomes `SKILL.md`).
- **DATA** — static knowledge (patterns/chains/correlations) kept as-is.
- **REDUNDANT** — deterministic orchestration that duplicates what the LLM
  already does; remove or fold into a TOOL/SKILL.

The guiding principle: **the LLM is the brain; Blitz Strike is the deterministic
hands + knowledge + guardrails.** A deterministic "self-driving loop" that tries
to BE the brain is the anti-pattern being removed.

---

## src/mission/ — classification

| File | Component | Verdict | Why |
|------|-----------|---------|-----|
| `types.ts` | shared types (Mission/Task/Hypothesis/Budget/Graph) | **DATA** | Type contracts. Reshape `Mission`→`Engagement` later, but keep as the shared layer. |
| `state.ts` | `createMission`/`save`/`load`/`list`/`delete` | **TOOL** | Persistence is useful — repurpose as *engagement/finding state* the LLM drives, not an "autonomous mission" blob. |
| `taskgraph.ts` | `schedule`/`nextBatch`/`allResolved` | **REDUNDANT** | Task scheduling is the LLM's plan-agent job. |
| `graph.ts` | Security Graph (nodes/edges/stats/merge) | **TOOL** | The finding-relationship graph is genuinely useful for the LLM to track + query. |
| `hypothesis.ts` | Hypothesis Engine (make/validate/reject/merge) | **TOOL** | Core moat — evidence-first `observation→hypothesis→validated→rejected` lifecycle. LLM calls these per finding. |
| `control.ts` | `runMission` loop + `buildInitialTasks` + `replan` | **REDUNDANT** | The self-driving scheduler loop — the LLM drives this instead. |
| `control.ts` | `scopeAllowed` | **TOOL** | Scope guardrail (keep + expose as a check the LLM MUST call before live actions). |
| `planner.ts` | `ATTACK_BRANCHES` + escalation graph | **SKILL** | Knowledge: which attack branches/escapes exist. Becomes `SKILL.md` + data. |
| `planner.ts` | `planNextActions` (ranking) | **TOOL** | Deterministic confidence×value−risk ranking the LLM can use as a hint. |
| `coverage.ts` | `computeCoverage`/`coverageGaps` | **TOOL** | LLM calls to find un-covered dimensions. `COVERAGE_DIMENSIONS` → **SKILL**. |
| `recovery.ts` | `diagnoseError`/`recoveryDecision` | **TOOL** | LLM calls on failure to pick retry/alternative. `AGENT_ALTERNATIVES` → **SKILL**. |
| `memory.ts` | `persistMissionMemory`/`recallForTarget` | **TOOL** | Cross-session memory (keep — the LLM's long-term finding store). |
| `reviewer.ts` | `reviewFinding`/`reviewValidated` (10 questions) | **TOOL** | Adversarial reviewer — key moat. LLM calls before CONFIRMING a finding. |
| `router.ts` | `routeTask`/`AGENT_TIER` | **REDUNDANT** | Model routing is the LLM platform's own job (or a small TOOL hint). |
| `budget.ts` | `budgetStatus`/`budgetOverrun`/`consumeTasks` | **TOOL** | LLM calls to check budget. The "terminate on overrun" auto-decision is **REDUNDANT**. |
| `termination.ts` | `evaluateTermination`/`applyTermination` | **REDUNDANT** | The LLM decides when to stop; the 7 reasons → **SKILL** doctrine. |
| `benchmark.ts` + `enterprise-benchmark.ts` | benchmark runners | **DATA/QA** | Keep — not runtime brain; QA harness. |
| `cli.ts` | `mission` CLI subcommands | **REDUNDANT** | Deterministic-brain CLI. Optional standalone fallback; LLM drives via MCP. |
| `mcp.ts` | `registerMissionTools` (mission_start/status/…) | **REDUNDANT** | Replace with skill/tool MCP tools (the LLM drives granular tools). |

## src/agents.ts — 13 agents

Each agent is a deterministic executor = orchestration (REDUNDANT) + detection
calls (TOOL). The agent's *responsibility + tool list* becomes a **SKILL**.

| Agent | Repurpose as SKILL | Kept as TOOL |
|-------|--------------------|--------------|
| `commander` | orchestration doctrine (plan → delegate → verify → report) | — (LLM is the commander) |
| `recon` | passive recon doctrine | `activeScan`/`live_recon` (already MCP tools) |
| `web` | live web-attack doctrine | `strike_verify`/`browser_validate` |
| `api` | API recon/authz doctrine | `api` detection tools |
| `source` | source-audit doctrine | `analyzeDataFlow2` + `detectRouteConfusion` + `detectComplexBugs` |
| `auth` | auth-gap doctrine | auth detection |
| `analysis` | multi-language taint doctrine | `analyzeTaintUniversal` |
| `validator` | verification doctrine (marker + negative) | `strikeVerify` |
| `reviewer` | adversarial-review doctrine | `reviewFinding` (TOOL above) |
| `reporter` | report-writing doctrine | report generator |
| `browser` | browser-session doctrine | `browser-agent.ts` (session ops) |
| `mobile` | mobile RE doctrine | mobile analysis |
| `cloud` | cloud-enum doctrine | cloud tools |

## src/browser-agent.ts

Session-based browser automation → **TOOL** (LLM calls `browser_agent` op).
Keep as-is.

## src/server.ts (69 MCP tools)

**KEEP** — the deterministic analysis/verification/evidence tools are the moat.
Add `instructions` + `next_steps` per tool for LLM ergonomics.

---

## Net outcome

- **Keep as TOOL (moat):** taint engine, universal taint, route-confusion,
  complex-bugs, strike_verify, hypothesis engine, security graph, adversarial
  reviewer, coverage, recovery, budget-status, memory, scope gate, browser agent.
- **Become SKILL:** 13 agent doctrines, reviewer 10-questions, coverage
  dimensions, attack branches, escalation graph, termination reasons, recovery
  alternatives.
- **Remove (REDUNDANT):** `runMission` loop, task scheduler, replan, model
  router, termination auto-decision, `mission` CLI, `registerMissionTools`.

The deterministic analysis stays; the deterministic *orchestration* goes.
