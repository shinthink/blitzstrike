/** Goal tracking — a lightweight goal ledger.
 *
 *  Simple: goals are FREE-TEXT (with an optional quantitative condition the agent
 *  must check before marking met). No typed/deterministic engine — just a place to
 *  record the engagement's goals and prove them one by one. "all_met" flips true
 *  when every goal is met, which is the task's completion signal.
 */

export interface Goal {
  id: string;
  text: string;
  /** Optional quantitative condition (free-text), e.g. "coverage >= 80%". */
  condition?: string;
  status: "pending" | "met";
  met_evidence?: string;
  met_reason?: string;
  /** Parent goal id, when this is a sub-goal of a decomposed goal. */
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

/** The standard sub-goal breakdown for a pentest/audit engagement. Deterministic
 *  — a high-level "audit X" always decomposes into these six phases. */
const STANDARD_SUBGOALS: Array<{ text: string; condition: string }> = [
  { text: "ENUMERATION — discover every in-scope asset", condition: "every host/subdomain/endpoint enumerated (asset_discovery)" },
  { text: "SURFACE — map every endpoint, parameter, and action", condition: "coverage >= 100% (every surface item has a terminal verdict)" },
  { text: "DISCOVERY — find vulnerabilities across every class", condition: "each eligible class × shape carries a terminal verdict" },
  { text: "VERIFICATION — verify each hypothesis live", condition: "every hypothesis verified (strike_verify/OOB) or refuted" },
  { text: "ESCALATION — drive each finding to real impact", condition: "every foothold escalated to records/admin/PII or genuinely blocked" },
  { text: "REPORT — write findings", condition: "generate_report run; zero open obligations" },
];

/** Register one or more goals. Returns the full goal list. */
export function setGoals(texts: Array<string | { text: string; condition?: string; parent_id?: string }>): Goal[] {
  for (const t of texts) {
    const text = typeof t === "string" ? t : t.text;
    const condition = typeof t === "string" ? undefined : t.condition;
    const parent_id = typeof t === "string" ? undefined : t.parent_id;
    const now = new Date().toISOString();
    goals.push({ id: nextId(), text, condition, status: "pending", ...(parent_id ? { parent_id } : {}), created: now, updated: now });
  }
  return [...goals];
}

/** Decompose a high-level goal into the standard six-phase sub-goal plan. Returns
 *  the parent goal + its sub-goals (all registered in the ledger, all pending). */
export function decomposeGoal(text: string): { parent: Goal; sub_goals: Goal[] } {
  const now = new Date().toISOString();
  const parent: Goal = { id: nextId(), text, status: "pending", created: now, updated: now };
  goals.push(parent);
  const sub_goals: Goal[] = [];
  for (const sg of STANDARD_SUBGOALS) {
    const g: Goal = { id: nextId(), text: sg.text, condition: sg.condition, status: "pending", parent_id: parent.id, created: now, updated: now };
    goals.push(g);
    sub_goals.push(g);
  }
  return { parent, sub_goals };
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

/** Current goal state + whether every goal is met. */
export function goalStatus(): { goals: Goal[]; all_met: boolean; met: number; total: number } {
  const met = goals.filter((g) => g.status === "met").length;
  return { goals: [...goals], all_met: goals.length > 0 && met === goals.length, met, total: goals.length };
}

/** The goal hierarchy: top-level goals and their sub-goals. */
export function goalTree(): { parent: Goal; children: Goal[]; children_met: number }[] {
  const parents = goals.filter((g) => !g.parent_id);
  return parents.map((p) => {
    const children = goals.filter((g) => g.parent_id === p.id);
    return { parent: p, children, children_met: children.filter((c) => c.status === "met").length };
  });
}
