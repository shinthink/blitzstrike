/** Constraint Registry — deterministic operation allow/deny red lines.
 *
 *  The engagement's "operation constraints" are the highest-priority red line:
 *  they bound WHAT the agent is allowed to DO (not just which targets are in
 *  scope). Unlike a free-text note, every constraint here is a TYPED rule that a
 *  deterministic checker evaluates — the agent can ASK `constraint_check` before
 *  an action and get a machine answer (fail-closed), instead of hoping a prose
 *  note is respected.
 *
 *  Semantics:
 *    - DENY rules always win (deny-priority).
 *    - default_mode "denylist" (default) = allow everything except explicit denies.
 *    - default_mode "allowlist" = ONLY explicit allow rules pass (fail-closed) —
 *      used for "passive-only" / "only these ports" engagements.
 *    - action "active" is an UMBRELLA that matches every active op (brute force,
 *      scan, exploit, upload, …); action "*" matches everything.
 *    - target is an optional host/port/param glob (`*`/`?`); unset = applies to all.
 */

export type ConstraintAction =
  | "probe"          // a single benign request (baseline/differential)
  | "brute_force"    // credential/password brute forcing
  | "scan"           // broad port/endpoint/vuln scanning
  | "enumerate"      // directory/endpoint/user enumeration
  | "upload"         // file upload / write-to-target
  | "exploit"        // active exploitation (payload delivery / RCE / SQLi)
  | "write"          // any state-changing write to the target
  | "exfiltrate"     // pulling data out of the target
  | "dos"            // denial of service / resource exhaustion
  | "social_eng"     // social engineering / phishing
  | "credential_use" // using discovered credentials to log in
  | "active"         // UMBRELLA: any of the active ops above
  | "*";             // wildcard: every action

export type ConstraintMode = "allow" | "deny";
export type ConstraintDefaultMode = "denylist" | "allowlist";

export interface Constraint {
  id: string;
  mode: ConstraintMode;
  action: ConstraintAction;
  /** Optional host/port/param glob (`*`/`?`). Unset = applies to every target. */
  target?: string;
  reason: string;
  created: string;
}

/** Actions the "active" umbrella covers. */
const ACTIVE_ACTIONS: ReadonlySet<ConstraintAction> = new Set([
  "brute_force", "scan", "enumerate", "upload", "exploit", "write", "exfiltrate", "dos", "social_eng", "credential_use",
]);

let defaultMode: ConstraintDefaultMode = "denylist";
let constraints: Constraint[] = [];
let counter = 0;

function nextId(): string {
  counter += 1;
  return `CST-${String(counter).padStart(4, "0")}`;
}

function globToRegex(g: string): RegExp {
  const esc = g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${esc}$`, "i");
}

/** Does a rule action match the action being checked? */
export function actionMatches(rule: ConstraintAction, action: string): boolean {
  if (rule === "*") return true;
  if (rule === action) return true;
  if (rule === "active" && ACTIVE_ACTIONS.has(action as ConstraintAction)) return true;
  return false;
}

/** Does a rule target glob match the target being checked?
 *  - rule unscoped (no target) → applies to every target.
 *  - rule scoped but the check passes NO target → NO match (ambiguous — we can't
 *    confirm the action is inside the scoped rule's range, so it must not fire). */
export function targetMatches(ruleTarget: string | undefined, target: string | undefined): boolean {
  if (!ruleTarget) return true;
  if (!target) return false;
  if (target === ruleTarget) return true;
  return globToRegex(ruleTarget).test(target);
}

/** Add or replace a constraint rule. Returns the stored rule. */
export function setConstraint(input: {
  mode: ConstraintMode;
  action: ConstraintAction;
  target?: string;
  reason: string;
}): Constraint {
  const rule: Constraint = {
    id: nextId(),
    mode: input.mode,
    action: input.action,
    target: input.target,
    reason: input.reason,
    created: new Date().toISOString(),
  };
  constraints.push(rule);
  return rule;
}

/** Set the default mode: denylist (allow-all-except-denies) or allowlist (fail-closed). */
export function setDefaultMode(mode: ConstraintDefaultMode): void {
  defaultMode = mode;
}

/** List every active constraint + the default mode. */
export function listConstraints(): { default_mode: ConstraintDefaultMode; constraints: Constraint[] } {
  return { default_mode: defaultMode, constraints: [...constraints] };
}

/** Remove a constraint by id. Returns true if it existed. */
export function clearConstraint(id: string): boolean {
  const before = constraints.length;
  constraints = constraints.filter((c) => c.id !== id);
  return constraints.length < before;
}

export interface ConstraintVerdict {
  allowed: boolean;
  mode: ConstraintMode | ConstraintDefaultMode;
  matched: string | null;
  reason: string;
}

/**
 * Deterministic check: is `action` on `target` allowed?
 *   1. DENY rules always win.
 *   2. allowlist mode fails closed — an explicit allow is required.
 *   3. denylist mode default-allows.
 */
export function checkConstraint(action: string, target?: string): ConstraintVerdict {
  const deny = constraints.find((c) => c.mode === "deny" && actionMatches(c.action, action) && targetMatches(c.target, target));
  if (deny) {
    return { allowed: false, mode: "deny", matched: deny.id, reason: deny.reason };
  }
  const allow = constraints.find((c) => c.mode === "allow" && actionMatches(c.action, action) && targetMatches(c.target, target));
  if (defaultMode === "allowlist") {
    if (allow) return { allowed: true, mode: "allow", matched: allow.id, reason: allow.reason };
    return { allowed: false, mode: "allowlist", matched: null, reason: `allowlist mode: no allow rule covers action '${action}'${target ? ` on '${target}'` : ""}` };
  }
  if (allow) return { allowed: true, mode: "allow", matched: allow.id, reason: allow.reason };
  return { allowed: true, mode: "denylist", matched: null, reason: "denylist mode: no deny rule matches — default allow" };
}

/** Render the active red lines for injection into the agent's system prompt. */
export function renderConstraints(): string {
  if (constraints.length === 0) return "";
  const deny = constraints.filter((c) => c.mode === "deny");
  const allow = constraints.filter((c) => c.mode === "allow");
  const lines: string[] = [];
  lines.push(`OPERATION CONSTRAINTS (red line — highest priority; default_mode=${defaultMode}${defaultMode === "allowlist" ? ", FAIL-CLOSED" : ""}):`);
  for (const c of deny) lines.push(`  - DENY ${c.action}${c.target ? ` @ ${c.target}` : ""}: ${c.reason} (${c.id})`);
  for (const c of allow) lines.push(`  - ALLOW ${c.action}${c.target ? ` @ ${c.target}` : ""}: ${c.reason} (${c.id})`);
  lines.push("Before any action, self-check against these via constraint_check(action, target); a DENY match is absolute — do not do it even if a route/intent implies it.");
  return lines.join("\n");
}
