/** Audit log (§45) — structured, append-only audit events.
 *
 * Every security-relevant action in Blitz Strike emits a structured audit
 * event so the whole pipeline is auditable: who did what, to what target, with
 * what result, tied together by a correlation id.
 *
 * Location: $BLITZSTRIKE_HOME/audit.jsonl (default ~/.blitzstrike/audit.jsonl).
 */
import { appendFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { VERSION } from "./version.js";

const HOME_DIR = process.env.BLITZSTRIKE_HOME ?? join(homedir(), ".blitzstrike");
const AUDIT_PATH = join(HOME_DIR, "audit.jsonl");

export type AuditEvent =
  | "scope_checked"
  | "tool_started"
  | "tool_finished"
  | "chain_started"
  | "chain_finished"
  | "finding_created"
  | "finding_updated"
  | "validation_started"
  | "validation_finished"
  | "evidence_created"
  | "memory_written"
  | "secret_redacted";

export interface AuditRecord {
  timestamp: string;
  event: AuditEvent;
  actor: string;
  tool?: string;
  tool_version?: string;
  target?: string;
  result?: string;
  correlationId?: string;
}

export interface AuditOptions {
  actor?: string;
  tool?: string;
  target?: string;
  result?: string;
  correlationId?: string;
}

/** Append a structured audit event. Returns the record (also persisted). */
export function recordAudit(event: AuditEvent, opts: AuditOptions = {}): AuditRecord {
  const record: AuditRecord = {
    timestamp: new Date().toISOString(),
    event,
    actor: opts.actor ?? "system",
    tool: opts.tool,
    tool_version: VERSION,
    target: opts.target,
    result: opts.result,
    correlationId: opts.correlationId,
  };

  try {
    if (!existsSync(HOME_DIR)) mkdirSync(HOME_DIR, { recursive: true });
    appendFileSync(AUDIT_PATH, JSON.stringify(record) + "\n");
  } catch {
    // Audit must never crash the pipeline — best-effort persistence.
  }

  return record;
}

/** Read all audit records (newest last). */
export function listAudit(): AuditRecord[] {
  try {
    if (!existsSync(AUDIT_PATH)) return [];
    return readFileSync(AUDIT_PATH, "utf8")
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l) as AuditRecord);
  } catch {
    return [];
  }
}
