/**
 * BlitzStrike task checkpoint journal — per-workstream progress + resume.
 * Each delegated task has an ordered plan; every step records a checkpoint.
 * A failed workstream can be RESUMED from its last completed checkpoint
 * (not restarted), and the orchestrator can see the exact progress + remaining
 * steps of every task at a glance. On-disk, so checkpoints survive restarts.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

function tasksDir(): string {
  return join(fileURLToPath(new URL(".", import.meta.url)), "..", ".blitzstrike", "tasks");
}

function taskPath(id: string): string {
  return join(tasksDir(), `${id}.json`);
}

export interface TaskCheckpoint {
  step: string;
  status: "in_progress" | "done" | "failed" | "blocked";
  output_hash?: string;
  note?: string;
  ts: number;
}

export interface TaskRecord {
  task_id: string;
  objective: string;
  plan: string[];
  current_step: string;
  status: "pending" | "in_progress" | "done" | "failed" | "blocked";
  checkpoints: TaskCheckpoint[];
  created_ts: number;
  updated_ts: number;
}

function load(id: string): TaskRecord | null {
  try {
    return JSON.parse(readFileSync(taskPath(id), "utf8")) as TaskRecord;
  } catch {
    return null;
  }
}

function save(t: TaskRecord): void {
  mkdirSync(tasksDir(), { recursive: true });
  writeFileSync(taskPath(t.task_id), JSON.stringify(t, null, 2));
}

export function taskStart(id: string, objective: string, plan: string[]): Record<string, unknown> {
  const now = Date.now();
  const t: TaskRecord = {
    task_id: id,
    objective,
    plan,
    current_step: plan[0] ?? "complete",
    status: plan.length ? "in_progress" : "done",
    checkpoints: [],
    created_ts: now,
    updated_ts: now,
  };
  save(t);
  return { ...t, progress: `0/${plan.length}`, next: t.current_step };
}

export function taskCheckpoint(
  id: string,
  step: string,
  status: TaskCheckpoint["status"],
  note?: string,
  outputHash?: string,
): Record<string, unknown> {
  const t = load(id);
  if (!t) return { ok: false, error: `task '${id}' not found — call task_start first` };
  t.checkpoints.push({ step, status, output_hash: outputHash, note, ts: Date.now() });
  t.updated_ts = Date.now();
  const idx = t.plan.indexOf(step);
  if (status === "done") {
    t.current_step = idx >= 0 && idx + 1 < t.plan.length ? t.plan[idx + 1] : "complete";
    if (t.current_step === "complete") t.status = "done";
  } else if (status === "failed") {
    t.status = "failed";
  } else if (status === "blocked" && t.status !== "failed") {
    t.status = "blocked";
  }
  save(t);
  return {
    task_id: id,
    step,
    status,
    current_step: t.current_step,
    progress: `${t.checkpoints.filter((c) => c.status === "done").length}/${t.plan.length}`,
    next: t.current_step,
  };
}

export function taskStatus(id: string): Record<string, unknown> {
  const t = load(id);
  if (!t) return { found: false, error: `task '${id}' not found` };
  const done = t.checkpoints.filter((c) => c.status === "done").length;
  return {
    found: true,
    task_id: t.task_id,
    objective: t.objective,
    status: t.status,
    current_step: t.current_step,
    progress: `${done}/${t.plan.length}`,
    remaining: t.plan.slice(t.plan.indexOf(t.current_step)),
    checkpoints: t.checkpoints,
  };
}

export function taskResume(id: string): Record<string, unknown> {
  const t = load(id);
  if (!t) return { found: false, error: `task '${id}' not found` };
  const doneSteps = t.checkpoints.filter((c) => c.status === "done").map((c) => c.step);
  const remaining = t.plan.filter((s) => !doneSteps.includes(s));
  const last = t.checkpoints[t.checkpoints.length - 1];
  return {
    found: true,
    task_id: id,
    status: t.status,
    resume_from: t.current_step,
    already_done: doneSteps,
    remaining_steps: remaining,
    last_checkpoint: last ?? null,
    instruction:
      t.status === "done"
        ? "task complete — nothing to resume"
        : `resume '${id}' at step '${t.current_step}'. Completed: [${doneSteps.join(", ") || "none"}]. ` +
          `Remaining: [${remaining.join(", ") || "none"}]. Re-dispatch with the FAILED context (not fresh): ` +
          `'RESUME ${id}: you already completed [${doneSteps.join(", ")}]; continue from '${t.current_step}'.'`,
  };
}
