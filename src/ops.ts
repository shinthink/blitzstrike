/**
 * BlitzStrike orchestration ops — the "agent-runtime" features (planning,
 * delegation, worktree isolation, watchdog, context pruning) implemented as
 * deterministic functions the LLM calls, instead of host-agent infrastructure.
 * Every function is pure logic: no LLM, no side effects except `worktree`.
 */
import { execSync, execFileSync } from "node:child_process";

// ---------------------------------------------------------------------------
// Delegation — decompose a task list into parallel-first batches (named deps).
// ---------------------------------------------------------------------------
export interface DelegationTask {
  id: string;
  objective: string;
  depends_on?: string[];
}

export interface DelegationBatch {
  batch: number;
  parallel: string[];
  sequential: boolean;
  blocked_by: string[];
}

export function decomposeBatches(tasks: DelegationTask[]): { batches: DelegationBatch[]; total: number } {
  const remaining = [...tasks];
  const done = new Set<string>();
  const batches: DelegationBatch[] = [];
  let n = 1;
  while (remaining.length) {
    const ready = remaining.filter((t) => (t.depends_on ?? []).every((d) => done.has(d)));
    if (ready.length === 0) {
      // cycle / broken dependency — fire the head sequentially to unblock progress
      const head = remaining[0];
      batches.push({ batch: n++, parallel: [head.id], sequential: true, blocked_by: head.depends_on ?? [] });
      done.add(head.id);
      remaining.splice(0, 1);
      continue;
    }
    const blockedBy = [...new Set(ready.flatMap((t) => t.depends_on ?? []))];
    batches.push({ batch: n++, parallel: ready.map((t) => t.id), sequential: blockedBy.length > 0, blocked_by: blockedBy });
    for (const t of ready) {
      done.add(t.id);
      remaining.splice(remaining.indexOf(t), 1);
    }
  }
  return { batches, total: tasks.length };
}

export function retryPattern(failure: string): Record<string, unknown> {
  return {
    rule: "no retry cap — diagnose, attach a plan, resume the SAME workstream until verified",
    on_failure: [
      `1. diagnose what '${failure || "the workstream"}' actually returned (read its output, not its claim)`,
      "2. re-dispatch with the FAILED context, not a fresh start: 'FAILED: {error}. Diagnosis: {observation}. Fix by: {specific instruction}'",
      "3. if it loops on the same broken approach, spawn a NEW workstream with a different angle + the failed attempts as context",
      "4. never move on unverified",
    ],
  };
}

// ---------------------------------------------------------------------------
// Worktree — isolated git worktree for a parallel workstream (no file conflict).
// ---------------------------------------------------------------------------
export function worktree(action: "add" | "list" | "remove", path?: string, branch?: string): Record<string, unknown> {
  try {
    if (action === "list") {
      const out = execSync("git worktree list --porcelain", { encoding: "utf8" }).trim();
      return { action, ok: true, worktrees: out };
    }
    if (action === "add") {
      if (!path) return { action, ok: false, error: "path is required for worktree add" };
      const b = branch ?? `blitz-${Date.now().toString(36)}`;
      // execFileSync (no shell) — branch + path are literal argv, not shell text.
      const out = execFileSync("git", ["worktree", "add", "-b", b, path], { encoding: "utf8" }).trim();
      return { action, ok: true, branch: b, path, out };
    }
    if (action === "remove") {
      if (!path) return { action, ok: false, error: "path is required for worktree remove" };
      execFileSync("git", ["worktree", "remove", path, "--force"], { encoding: "utf8" });
      return { action, ok: true, path };
    }
    return { action, ok: false, error: "unknown action (use add | list | remove)" };
  } catch (e) {
    return { action, ok: false, error: String((e as Error)?.message ?? e) };
  }
}

// ---------------------------------------------------------------------------
// Watchdog — detect a stalled phase so the LLM intervenes instead of looping.
// ---------------------------------------------------------------------------
export function watchdog(phase: string, hypotheses: number, lastActivityMs: number, nowMs = Date.now()): Record<string, unknown> {
  const idleSeconds = Math.round((nowMs - lastActivityMs) / 1000);
  const stalled = idleSeconds > 15 * 60; // > 15 min idle
  const status = stalled ? "STALLED" : hypotheses > 0 ? "PROGRESSING" : "IDLE";
  return {
    phase,
    hypotheses,
    idle_seconds: idleSeconds,
    status,
    action: stalled
      ? "STALLED — intervene: widen the surface (live_recon/enrich_scan/blitz_scan), call model_fallback + retry_guidance if a model/sub-agent died, or advance to the next phase"
      : hypotheses > 0
        ? "PROGRESSING — keep driving the current phase; verify each hypothesis (strike_verify) before moving on"
        : "IDLE — no hypotheses yet: the surface is not mapped. Run live_recon/enrich_scan before declaring the phase done",
  };
}

// ---------------------------------------------------------------------------
// Context pruning — compact the engagement state so the LLM can drop raw detail.
// ---------------------------------------------------------------------------
export function compactState(phase: string, findings: Array<Record<string, unknown>>): Record<string, unknown> {
  const confirmed = findings.filter((f) => f.status === "confirmed" || f.status === "validating").length;
  const pending = findings.filter((f) => f.status === "hypothesis" || f.status === "pending").length;
  const rejected = findings.filter((f) => f.status === "false_positive" || f.status === "rejected").length;
  const top = findings
    .filter((f) => f.status === "confirmed" || f.status === "hypothesis")
    .slice(0, 10)
    .map((f) => ({ title: f.title, severity: f.severity, status: f.status }));
  return {
    phase,
    summary: `${confirmed} confirmed, ${pending} pending, ${rejected} rejected`,
    top_findings: top,
    note: "Drop the raw detail you are holding and keep ONLY this compact state. The engagement tracker (engagement_track / engagement_status) is the source of truth — re-read it instead of relying on memory.",
  };
}
