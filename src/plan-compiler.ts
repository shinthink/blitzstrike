/** Plan compiler — the "LLM proposes, deterministic code validates" seam.
 *
 * An LLM produces a plan (an ordered list of tasks); this pure-function
 * compiler REJECTS invalid plans BEFORE they can mutate any state:
 *
 *   1. scope        — every task target must be byte-for-byte within scope
 *   2. hygiene      — no control chars / malformed host (canonical URL parse)
 *   3. duplicate    — no two tasks with the same kind + target + objective
 *   4. dependency   — depends_on must reference real tasks, and no cycles
 *   5. phase order  — a task cannot jump a phase (exploit before test, etc.)
 *   6. coverage     — every required vuln class must have a task OR a typed
 *                     disposition (not_applicable / blocked_* / exhausted /
 *                     superseded)
 *
 * The verdict is deterministic: `valid` is true only when there are zero
 * rejected tasks AND zero uncovered required classes. A plan that fails to
 * compile is returned with per-task reasons — the model fixes it, not the
 * runtime.
 */

export type TaskKind = "discover" | "enumerate" | "test" | "exploit" | "verify" | "recover";

export interface PlanTarget {
  url?: string;
  host?: string;
  port?: number;
}

export interface PlanTask {
  id: string;
  kind: TaskKind;
  target: PlanTarget;
  objective: string;
  /** Vuln class this task hunts (used by the coverage floor). */
  vuln_class?: string;
  /** IDs of tasks this task depends on. */
  depends_on?: string[];
}

export type DispositionReason =
  | "not_applicable"
  | "blocked_missing_auth"
  | "blocked_missing_second_identity"
  | "blocked_unreachable"
  | "blocked_policy"
  | "exhausted"
  | "superseded";

export interface PlanDisposition {
  vuln_class: string;
  reason: DispositionReason;
  note?: string;
}

export interface CompilePlanInput {
  tasks: PlanTask[];
  scope: { allowed_hosts: string[] };
  required_classes: string[];
  dispositions?: PlanDisposition[];
}

export interface RejectedTask {
  id: string;
  reason: string;
}

export interface CompilePlanResult {
  valid: boolean;
  accepted: PlanTask[];
  rejected: RejectedTask[];
  coverage: {
    missing: string[];
    covered: string[];
    dispositioned: string[];
  };
  diagnostics: string[];
}

const PHASE_INDEX: Record<TaskKind, number> = { discover: 0, enumerate: 1, test: 2, exploit: 3, verify: 4, recover: 5 };

/** Minimum prior phase required on the SAME target before a task of this kind.
 *  `recover` addresses a FAILED task of ANY kind, so its floor is `discover`
 *  (any prior task on the target), not `test`. */
const MIN_PRIOR_PHASE: Partial<Record<TaskKind, TaskKind>> = {
  enumerate: "discover",
  test: "enumerate",
  exploit: "test",
  verify: "test",
  recover: "discover",
};

/** Extract the host (hostname) from a task target. */
function targetHost(target: PlanTarget): string {
  if (target.url) {
    try {
      return new URL(target.url).hostname;
    } catch {
      return target.url; // falls through to hygiene rejection
    }
  }
  return (target.host ?? "").replace(/^\[|\]$/g, "");
}

function hostInScope(host: string, allowed: string[]): boolean {
  const h = host.toLowerCase().trim();
  if (!h) return false;
  for (const a of allowed) {
    const aa = a.toLowerCase().trim();
    if (aa === "*") return true;
    if (h === aa) return true;
    if (h.endsWith("." + aa)) return true; // subdomain of an allowed domain
  }
  return false;
}

function targetHygiene(host: string): string | null {
  if (!host) return "empty host";
  if (/[\x00-\x1f\x7f]/.test(host)) return "control characters in host";
  // hostname, IPv4, or bracketed IPv6
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$|^[0-9a-f:]+$/i.test(host)) return "malformed host";
  return null;
}

function hasCycle(startId: string, byId: Map<string, PlanTask>, currentId: string, path: Set<string>): boolean {
  if (path.has(currentId)) return true;
  const t = byId.get(currentId);
  if (!t) return false;
  path.add(currentId);
  for (const d of t.depends_on ?? []) {
    if (hasCycle(startId, byId, d, path)) return true;
  }
  path.delete(currentId);
  return false;
}

/** Compile (validate) an LLM-proposed plan against scope + phase + coverage rules. */
export function compilePlan(input: CompilePlanInput): CompilePlanResult {
  const { tasks, scope, required_classes, dispositions = [] } = input;
  const accepted: PlanTask[] = [];
  const rejected: RejectedTask[] = [];
  const diagnostics: string[] = [];

  const ids = new Set(tasks.map((t) => t.id));
  const byId = new Map(tasks.map((t) => [t.id, t]));
  const seen = new Map<string, string>(); // signature -> id

  tasks.forEach((t, idx) => {
    const problems: string[] = [];
    const h = targetHost(t.target);

    const hygiene = targetHygiene(h);
    if (hygiene) problems.push(`hygiene: ${hygiene} (${h || "empty"})`);

    if (!hostInScope(h, scope.allowed_hosts)) problems.push(`out-of-scope: ${h || "empty"}`);

    const sig = `${t.kind}|${h}|${t.objective}`;
    if (seen.has(sig)) problems.push(`duplicate of task '${seen.get(sig)}'`);
    else seen.set(sig, t.id);

    for (const d of t.depends_on ?? []) {
      if (!ids.has(d)) problems.push(`dangling dependency '${d}'`);
    }

    if (hasCycle(t.id, byId, t.id, new Set())) problems.push("dependency cycle");

    const minPrior = MIN_PRIOR_PHASE[t.kind];
    if (minPrior) {
      const predecessors = tasks.filter((o, oi) => oi < idx || (t.depends_on ?? []).includes(o.id));
      const hasPrior = predecessors.some((o) => targetHost(o.target) === h && PHASE_INDEX[o.kind] >= PHASE_INDEX[minPrior]);
      if (!hasPrior) problems.push(`${t.kind} requires a prior ${minPrior} on ${h}`);
    }

    if (problems.length) rejected.push({ id: t.id, reason: problems.join("; ") });
    else accepted.push(t);
  });

  const covered = new Set<string>();
  for (const t of tasks) if (t.vuln_class) covered.add(t.vuln_class);
  const dispositioned = new Set<string>(dispositions.map((d) => d.vuln_class));
  const missing = required_classes.filter((c) => !covered.has(c) && !dispositioned.has(c));

  if (missing.length) diagnostics.push(`coverage gap: ${missing.join(", ")} have no task and no disposition`);
  if (rejected.length) diagnostics.push(`${rejected.length} task(s) rejected`);

  const valid = rejected.length === 0 && missing.length === 0;
  return {
    valid,
    accepted,
    rejected,
    coverage: { missing, covered: [...covered], dispositioned: [...dispositioned] },
    diagnostics,
  };
}
