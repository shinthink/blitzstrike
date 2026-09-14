// Engagement state — the deterministic bookkeeping hand for orchestration.
//
// The LLM is the brain (it plans, routes, delegates, judges). This module is
// the hands that keep the orchestration's state so the LLM never has to rely
// on its own memory for "where am I?" or "am I done?". It tracks the phase,
// the hypotheses, and computes a deterministic termination check from the
// orchestration lifecycle (scope → recon → analyze → deep → verify → report).

export interface EngagementHypothesis {
  sink: string;
  status: "pending" | "confirmed" | "rejected";
}

export interface EngagementState {
  id: string;
  target: string;
  kind: "source" | "live";
  phase: string;
  startedAt: string;
  hypotheses: EngagementHypothesis[];
}

const PHASES = ["scope", "recon", "analyze", "deep", "verify", "report"] as const;
type Phase = (typeof PHASES)[number];

let current: EngagementState | null = null;

function ts(): string {
  return new Date().toISOString();
}

export function startEngagement(target: string, kind: "source" | "live" = "source"): Record<string, unknown> {
  current = {
    id: `eng-${Date.now().toString(36)}`,
    target,
    kind,
    phase: "scope",
    startedAt: ts(),
    hypotheses: [],
  };
  return { started: true, ...current };
}

export function setPhase(phase: string): Record<string, unknown> {
  if (!current) return { found: false, error: "no active engagement — call engagement_start first" };
  const p = phase.toLowerCase().trim();
  if (!(PHASES as readonly string[]).includes(p)) {
    return { found: false, error: `unknown phase '${phase}'`, valid: PHASES };
  }
  current.phase = p as Phase;
  return { found: true, phase: current.phase };
}

export function trackHypothesis(sink: string, status: "pending" | "confirmed" | "rejected" = "pending"): Record<string, unknown> {
  if (!current) return { found: false, error: "no active engagement — call engagement_start first" };
  const existing = current.hypotheses.find((h) => h.sink === sink);
  if (existing) existing.status = status;
  else current.hypotheses.push({ sink, status });
  return { found: true, tracked: current.hypotheses.length };
}

export function engagementStatus(): Record<string, unknown> {
  if (!current) return { found: false, error: "no active engagement — call engagement_start first" };
  const pending = current.hypotheses.filter((h) => h.status === "pending").length;
  const confirmed = current.hypotheses.filter((h) => h.status === "confirmed").length;
  const rejected = current.hypotheses.filter((h) => h.status === "rejected").length;

  // Deterministic termination: done only when the engagement reached the report
  // phase AND every hypothesis is resolved. Emit the unmet criteria verbatim so
  // the LLM knows exactly what is left instead of "feeling" done.
  const unmet: string[] = [];
  if (current.phase !== "report") {
    unmet.push(`phase is '${current.phase}', not 'report' — the report has not been emitted`);
  }
  if (pending > 0) {
    unmet.push(`${pending} hypothesis(es) still pending — verify or reject each one`);
  }
  if (current.hypotheses.length === 0) {
    unmet.push("no hypotheses tracked — nothing was verified");
  }

  const idx = PHASES.indexOf(current.phase as Phase);
  const next = idx >= PHASES.length - 1 ? "done" : PHASES[idx + 1];

  return {
    found: true,
    id: current.id,
    target: current.target,
    kind: current.kind,
    phase: current.phase,
    startedAt: current.startedAt,
    hypotheses: current.hypotheses,
    counts: { pending, confirmed, rejected, total: current.hypotheses.length },
    termination: { done: unmet.length === 0, unmet },
    next_phase: next,
  };
}

// ---------------------------------------------------------------------------
// Engagement scaffolding — the folder + scope + state a hunt needs to start.
// ---------------------------------------------------------------------------

export interface EngagementScaffold {
  id: string;
  target: string;
  scope: string[];
  out_of_scope: string[];
  /** Folder layout the agent should materialize under the engagement dir. */
  structure: string[];
  /** Pre-filled scope.md template. */
  scope_md: string;
  state: Record<string, unknown>;
}

/** Scaffold an engagement: open its state, emit a folder layout + a scope.md
 *  template, and return the initial phase. Deterministic — no guesswork about
 *  "where do findings/evidence/reports go". */
export function scaffoldEngagement(target: string, scope: string[] = [], out_of_scope: string[] = []): EngagementScaffold {
  const state = startEngagement(target, "live");
  const scopeLines = (scope.length ? scope : [target]).map((s) => `- ${s}`).join("\n");
  const oosLines = (out_of_scope.length ? out_of_scope : ["(none declared)"]).map((s) => `- ${s}`).join("\n");
  const scopeMd = [
    `# Engagement scope`,
    ``,
    `**Target:** ${target}`,
    ``,
    `## In scope`,
    scopeLines,
    ``,
    `## Out of scope`,
    oosLines,
    ``,
    `## Accepted impact classes`,
    `- (paste the program's vulnerability-type / accepted-impact list here)`,
    ``,
    `## Testing rules`,
    `- (paste rate limits, prohibited areas, and any special rules here)`,
    ``,
  ].join("\n");

  return {
    id: state.id as string,
    target,
    scope,
    out_of_scope,
    structure: ["scope.md", "findings/", "evidence/", "reports/", "notes/"],
    scope_md: scopeMd,
    state,
  };
}
