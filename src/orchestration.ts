/** MCP Orchestration (Phase 7) — a true engagement engine.
 *
 * Turns the engagement lifecycle into an explicit state machine + deterministic
 * planner + risk policy, and emits §34 agent guidance at every step:
 *
 *   current_state / confidence / blocking_reason /
 *   required_evidence / recommended_next_action / recommended_tool
 *
 * The AI is the interpreter (reason / prioritize / correlate / summarize), but
 * it MUST NOT override scope, permissions, risk policy, validation verdict,
 * evidence integrity, or finding confirmation — those are enforced here.
 *
 * This deliberately does NOT add MCP tools; it deepens run_engagement().
 */

// ---------------------------------------------------------------------------
// State machine (data-driven)
// ---------------------------------------------------------------------------

export type EngagementState =
  | "scope_check"
  | "plan"
  | "recon"
  | "analyze"
  | "hypothesis"
  | "select_chain"
  | "validate"
  | "evidence"
  | "finding"
  | "report";

export interface StateDefinition {
  state: EngagementState;
  description: string;
  recommended_tools: string[];
  required_evidence: string[];
  next: EngagementState[];
  blocking?: string;
  confidence: "none" | "low" | "medium" | "high";
}

export const STATE_MACHINE: StateDefinition[] = [
  { state: "scope_check", description: "Validate target against scope + risk policy.", recommended_tools: ["scope_check"], required_evidence: ["scope_decision"], next: ["plan"], confidence: "high" },
  { state: "plan", description: "Derive the engagement plan from surface + scope.", recommended_tools: ["list_chains"], required_evidence: ["plan_steps"], next: ["recon"], confidence: "high" },
  { state: "recon", description: "Map the attack surface (endpoints, tech, WAF).", recommended_tools: ["blitz_scan", "active_scan", "fofa_search", "detect_waf"], required_evidence: ["attack_surface"], next: ["analyze"], confidence: "medium" },
  { state: "analyze", description: "Trace source→sink flows (interprocedural taint).", recommended_tools: ["eagle_eye2", "blitz_scan", "blitz_file"], required_evidence: ["sink_hits", "taint_flow"], next: ["hypothesis"], confidence: "medium" },
  { state: "hypothesis", description: "Form defensible hypotheses (static finding).", recommended_tools: ["blitz_file", "enrich_scan"], required_evidence: ["static_finding"], next: ["select_chain"], blocking: "live_validation_required", confidence: "high" },
  { state: "select_chain", description: "Match the hypothesis to an escalation chain.", recommended_tools: ["list_chains", "read_playbook"], required_evidence: ["matched_chain"], next: ["validate"], confidence: "high" },
  { state: "validate", description: "Verify live with baseline + marker + negative control.", recommended_tools: ["strike_verify", "browser_validate"], required_evidence: ["baseline", "marker_reflection", "negative_control"], next: ["evidence"], confidence: "medium" },
  { state: "evidence", description: "Attach hashable, provenance-bound evidence.", recommended_tools: ["finding_attach_evidence"], required_evidence: ["evidence_artifact"], next: ["finding"], confidence: "high" },
  { state: "finding", description: "Confirm the finding (invariants enforced).", recommended_tools: ["confirm_finding"], required_evidence: ["confirmed_finding"], next: ["report"], confidence: "high" },
  { state: "report", description: "Produce a reproducible report.", recommended_tools: ["report", "security-report"], required_evidence: ["report"], next: [], confidence: "high" },
];

export function stateDefinition(state: EngagementState): StateDefinition {
  return STATE_MACHINE.find((s) => s.state === state)!;
}

// ---------------------------------------------------------------------------
// Risk policy (data-driven)
// ---------------------------------------------------------------------------

export interface RiskPolicyRule {
  action: string;
  risk: "low" | "medium" | "high";
  requires_scope: boolean;
  destructive: boolean;
}

export const RISK_POLICY: RiskPolicyRule[] = [
  { action: "scope_check", risk: "low", requires_scope: false, destructive: false },
  { action: "blitz_scan", risk: "low", requires_scope: false, destructive: false },
  { action: "blitz_file", risk: "low", requires_scope: false, destructive: false },
  { action: "eagle_eye2", risk: "low", requires_scope: false, destructive: false },
  { action: "enrich_scan", risk: "low", requires_scope: false, destructive: false },
  { action: "detect_waf", risk: "low", requires_scope: false, destructive: false },
  { action: "fofa_search", risk: "low", requires_scope: false, destructive: false },
  { action: "list_chains", risk: "low", requires_scope: false, destructive: false },
  { action: "read_playbook", risk: "low", requires_scope: false, destructive: false },
  { action: "active_scan", risk: "medium", requires_scope: true, destructive: false },
  { action: "browser_validate", risk: "medium", requires_scope: true, destructive: false },
  { action: "strike_verify", risk: "high", requires_scope: true, destructive: false },
  { action: "confirm_finding", risk: "high", requires_scope: true, destructive: false },
];

export function riskOf(action: string): RiskPolicyRule | null {
  return RISK_POLICY.find((r) => r.action === action) ?? null;
}

/** Whether an action is permitted given scope + mode. */
export function actionPermitted(action: string, scopeAllowed: boolean, mode: string): boolean {
  const rule = riskOf(action);
  if (!rule) return true; // unknown action — not gated here
  if (mode === "ctf" || mode === "offensive" || mode === "reverse-engineering") return true;
  if (rule.requires_scope && !scopeAllowed) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Planner
// ---------------------------------------------------------------------------

export interface PlanStep {
  order: number;
  state: EngagementState;
  action: string;
  tool: string;
  evidence_required: string[];
  risk: "low" | "medium" | "high";
  permitted: boolean;
  status: "done" | "pending" | "blocked";
}

/** Build a deterministic plan from the state machine + scope/mode context. */
export function buildPlan(scopeAllowed: boolean, mode: string, executedState: EngagementState): PlanStep[] {
  const order = ["scope_check", "plan", "recon", "analyze", "hypothesis", "select_chain", "validate", "evidence", "finding", "report"] as EngagementState[];
  const executedIdx = order.indexOf(executedState);
  return order.map((state, i) => {
    const def = stateDefinition(state);
    const tool = def.recommended_tools[0] ?? "";
    const rule = riskOf(tool);
    const permitted = actionPermitted(tool, scopeAllowed, mode);
    const status: PlanStep["status"] = i <= executedIdx ? "done" : permitted ? "pending" : "blocked";
    return {
      order: i + 1,
      state,
      action: def.description,
      tool,
      evidence_required: def.required_evidence,
      risk: rule?.risk ?? "low",
      permitted,
      status,
    };
  });
}

// ---------------------------------------------------------------------------
// §34 Agent guidance
// ---------------------------------------------------------------------------

export interface Guidance {
  state: EngagementState;
  confidence: "none" | "low" | "medium" | "high";
  blocking_reason: string | null;
  required_evidence: string[];
  recommended_next_action: string;
  recommended_tool: string;
}

/** Compute §34 guidance for a state given the orchestration context. */
export function computeGuidance(state: EngagementState, scopeAllowed: boolean): Guidance {
  const def = stateDefinition(state);
  const next = def.next[0];
  const nextDef = next ? stateDefinition(next) : null;
  const tool = nextDef?.recommended_tools[0] ?? "";
  const permitted = actionPermitted(tool, scopeAllowed, "bug-bounty");
  return {
    state,
    confidence: def.confidence,
    blocking_reason: !scopeAllowed && nextDef && riskOf(tool)?.requires_scope ? "scope_required" : (def.blocking ?? null),
    required_evidence: def.required_evidence,
    recommended_next_action: nextDef?.description ?? "complete",
    recommended_tool: permitted ? tool : "",
  };
}
