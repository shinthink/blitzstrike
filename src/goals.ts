/** Goal ledger — final DELIVERABLES, not process steps.
 *
 *  A goal is a final, verifiable RESULT (e.g. "get RCE", "read admin PII",
 *  "take over the admin account") — NOT a process step. Recon, endpoint
 *  scanning, vuln analysis, attack steps, and verification are the HOW
 *  (they live in the process/exhaustion layer), never the WHAT (the goal).
 *
 *  Each goal can carry a vulnclass tag (rce/ato/priv-esc/…) and an optional
 *  quantitative condition the agent must verify before proving it met.
 */

export interface Goal {
  id: string;
  text: string;
  /** Vuln class this deliverable maps to (rce/ato/priv-esc/upload/reset/ajax-rest/…). */
  vulnclass?: string;
  /** Optional quantitative condition (free-text), e.g. "coverage >= 80%". */
  condition?: string;
  status: "pending" | "met";
  met_evidence?: string;
  met_reason?: string;
  /** Parent goal id, when this is a sub-deliverable of a decomposed goal. */
  parent_id?: string;
  created: string;
  updated: string;
}

let goals: Goal[] = [];
let counter = 0;

function nextId(): string {
  counter += 1;
  return `G-${String(counter).padStart(3, "0")}`;
}

/** The six-phase PROCESS plan — the HOW, exposed as a reference checklist.
 *  This is deliberately NOT registered into the goal ledger: goals are final
 *  deliverables, while these are the attack steps the doctrine/exhaustion
 *  layer drives. Conflating them makes "recon" look like a goal, which is the
 *  exact confusion the goal model forbids. */
export const PROCESS_PLAN: Array<{ phase: string; condition: string }> = [
  { phase: "ENUMERATION — discover every in-scope asset", condition: "every host/subdomain/endpoint enumerated (asset_discovery)" },
  { phase: "SURFACE — map every endpoint, parameter, and action", condition: "coverage >= 100% (every surface item has a terminal verdict)" },
  { phase: "DISCOVERY — find vulnerabilities across every class", condition: "each eligible class × shape carries a terminal verdict" },
  { phase: "VERIFICATION — verify each hypothesis live", condition: "every hypothesis verified (strike_verify/OOB) or refuted" },
  { phase: "ESCALATION — drive each finding to real impact", condition: "every foothold escalated to records/admin/PII or genuinely blocked" },
  { phase: "REPORT — write findings", condition: "generate_report run; zero open obligations" },
];

/** Register one or more final deliverables. Returns the full goal list. */
export function setGoals(texts: Array<string | { text: string; vulnclass?: string; condition?: string; parent_id?: string }>): Goal[] {
  for (const t of texts) {
    const text = typeof t === "string" ? t : t.text;
    const vulnclass = typeof t === "string" ? undefined : t.vulnclass;
    const condition = typeof t === "string" ? undefined : t.condition;
    const parent_id = typeof t === "string" ? undefined : t.parent_id;
    const now = new Date().toISOString();
    goals.push({ id: nextId(), text, status: "pending", ...(vulnclass ? { vulnclass } : {}), ...(condition ? { condition } : {}), ...(parent_id ? { parent_id } : {}), created: now, updated: now });
  }
  return [...goals];
}

/** Decompose a high-level goal into ONE final deliverable (optionally
 *  vulnclass-tagged) and return it alongside the decomposition RULES and the
 *  six-phase PROCESS plan. The process plan is reference-only — it is NOT
 *  registered as goals. Splitting a goal into MULTIPLE independent deliverables
 *  is the caller's (LLM's) job via goal_set; this tool registers the single
 *  deliverable and hands back the rules to do that split correctly. */
export function decomposeGoal(text: string, vulnclass?: string): {
  goal: Goal;
  rules: string[];
  process_plan: typeof PROCESS_PLAN;
} {
  const now = new Date().toISOString();
  const goal: Goal = { id: nextId(), text, status: "pending", ...(vulnclass ? { vulnclass } : {}), created: now, updated: now };
  goals.push(goal);
  const rules = [
    "A goal is a FINAL, verifiable deliverable — never a process step (recon/scan/vuln-analysis/attack-step/verification are NOT goals).",
    "One final result -> one goal; multiple INDEPENDENT deliverables -> separate goals (via goal_set), each with its own vulnclass.",
    "Never invent a goal the user did not state; tag vulnclass only when the deliverable maps to a clear class.",
    "Extract operation constraints (set_constraint) BEFORE decomposing; a constraint is self-contained (no pronouns — replace 'this target' with the concrete host/port).",
    "Minimal scope: only the exact target the user named; never widen a subdomain to its root domain.",
  ];
  return { goal, rules, process_plan: PROCESS_PLAN };
}

/** Mark a goal met, with the evidence that proved it + a reason. */
export function proveGoal(id: string, evidence: string, reason: string): { ok: boolean; goal?: Goal; error?: string } {
  const g = goals.find((x) => x.id === id);
  if (!g) return { ok: false, error: `no goal '${id}'` };
  g.status = "met";
  g.met_evidence = evidence;
  g.met_reason = reason;
  g.updated = new Date().toISOString();
  return { ok: true, goal: { ...g } };
}

/** Current goal state + whether every deliverable is met. */
export function goalStatus(): { goals: Goal[]; all_met: boolean; met: number; total: number } {
  const met = goals.filter((g) => g.status === "met").length;
  return { goals: [...goals], all_met: goals.length > 0 && met === goals.length, met, total: goals.length };
}

/** The goal hierarchy: top-level deliverables and their sub-deliverables. */
export function goalTree(): { parent: Goal; children: Goal[]; children_met: number }[] {
  const parents = goals.filter((g) => !g.parent_id);
  return parents.map((p) => {
    const children = goals.filter((g) => g.parent_id === p.id);
    return { parent: p, children, children_met: children.filter((c) => c.status === "met").length };
  });
}
