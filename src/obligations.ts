/** Proof-Obligation Engine — the deterministic ledger that keeps the LLM
 *  STRUCTURED (not by prompt, by construction).
 *
 *  Every hypothesis is a PROOF OBLIGATION: an open debt that must be discharged
 *  by evidence (verified) or refutation (refuted/blocked) before the engagement
 *  is complete. The LLM's job per turn is a SINGLE decision — "which obligation
 *  do I discharge next?" — and the ledger is the single source of truth for what
 *  work remains. COMPLETE/report is gated on zero open obligations.
 *
 *  Append-only JSONL. Location: $BLITZSTRIKE_HOME/obligations.jsonl.
 */
import { readFileSync, appendFileSync, mkdirSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { homedir } from "node:os";

const HOME_DIR = process.env.BLITZSTRIKE_HOME ?? join(homedir(), ".blitzstrike");
const OBLIGATION_PATH = join(HOME_DIR, "obligations.jsonl");

export type ObligationStatus = "open" | "verified" | "refuted" | "blocked";

export interface Obligation {
  id: string;
  claim: string;
  status: ObligationStatus;
  next_action: string;
  evidence_required: string;
  correlation_id?: string;
  created: string;
  discharged?: string;
}

function ensureDir(): void {
  if (!existsSync(HOME_DIR)) mkdirSync(HOME_DIR, { recursive: true });
}

function shortId(claim: string): string {
  return `obl-${createHash("sha256").update(`${claim}\u0000${Date.now()}`).digest("hex").slice(0, 12)}`;
}

export function loadObligations(): Obligation[] {
  if (!existsSync(OBLIGATION_PATH)) return [];
  try {
    const out: Obligation[] = [];
    for (const line of readFileSync(OBLIGATION_PATH, "utf8").split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        out.push(JSON.parse(t) as Obligation);
      } catch {
        /* skip corrupt line */
      }
    }
    return out;
  } catch {
    return [];
  }
}

function append(o: Obligation): void {
  ensureDir();
  appendFileSync(OBLIGATION_PATH, JSON.stringify(o) + "\n");
}

function rewrite(entries: Obligation[]): void {
  ensureDir();
  writeFileSync(OBLIGATION_PATH, entries.map((e) => JSON.stringify(e)).join("\n") + (entries.length ? "\n" : ""));
}

/** Create an open obligation (a proof debt the LLM must discharge). */
export function createObligation(input: {
  claim: string;
  next_action?: string;
  evidence_required?: string;
  correlation_id?: string;
}): Obligation {
  const o: Obligation = {
    id: shortId(input.claim),
    claim: input.claim.trim(),
    status: "open",
    next_action: input.next_action ?? "Verify live (strike_verify marker + negative control) or read-verify (verify_file_read), then strike_resolve.",
    evidence_required: input.evidence_required ?? "marker reflected + negative control inert (SHA-256-tagged evidence)",
    correlation_id: input.correlation_id,
    created: new Date().toISOString(),
  };
  append(o);
  return o;
}

export function listObligations(): Record<string, unknown> {
  const all = loadObligations();
  const open = all.filter((o) => o.status === "open");
  return {
    total: all.length,
    open: open.length,
    verified: all.filter((o) => o.status === "verified").length,
    refuted: all.filter((o) => o.status === "refuted").length,
    blocked: all.filter((o) => o.status === "blocked").length,
    done: all.length - open.length,
    // COMPLETE gate: an engagement is only complete when no proof debt remains.
    complete: open.length === 0,
    open_obligations: open.map((o) => ({ id: o.id, claim: o.claim, next_action: o.next_action, evidence_required: o.evidence_required, correlation_id: o.correlation_id, created: o.created })),
  };
}

/** SINGLE-DECISION LOOP: return the top open obligation + the exact deterministic
 *  test to discharge it. The LLM asks, then executes — it never plans from scratch. */
export function nextObligation(): Record<string, unknown> {
  const open = loadObligations().filter((o) => o.status === "open");
  if (open.length === 0) {
    return { done: true, note: "No open proof obligations — every hypothesis is verified/refuted/blocked. Proceed to generate_report." };
  }
  const next = open[0];
  return {
    done: false,
    remaining: open.length,
    obligation: {
      id: next.id,
      claim: next.claim,
      next_action: next.next_action,
      evidence_required: next.evidence_required,
      correlation_id: next.correlation_id,
    },
    instruction: `Discharge this obligation: ${next.next_action}. Evidence required: ${next.evidence_required}. Then discharge_obligation(id, status=verified|refuted|blocked).`,
  };
}

/** Discharge an obligation: verified (evidence-backed), refuted (false positive), or blocked. */
export function dischargeObligation(input: {
  id?: string;
  correlation_id?: string;
  status: Exclude<ObligationStatus, "open">;
  note?: string;
}): Record<string, unknown> {
  const all = loadObligations();
  const target = input.id
    ? all.find((o) => o.id === input.id)
    : input.correlation_id
      ? all.find((o) => o.correlation_id === input.correlation_id && o.status === "open")
      : undefined;
  if (!target) {
    return { discharged: false, error: "obligation not found", id: input.id, correlation_id: input.correlation_id };
  }
  if (target.status !== "open") {
    return { discharged: false, duplicate: true, id: target.id, note: `already ${target.status}` };
  }
  target.status = input.status;
  target.discharged = new Date().toISOString();
  rewrite(all);
  const remaining = all.filter((o) => o.status === "open").length;
  return {
    discharged: true,
    id: target.id,
    claim: target.claim,
    status: target.status,
    remaining_open: remaining,
    ...(remaining === 0 ? { hint: "All proof obligations discharged — proceed to generate_report." } : {}),
  };
}

/** Convenience: number of open obligations (for gating COMPLETE). */
export function openCount(): number {
  return loadObligations().filter((o) => o.status === "open").length;
}
