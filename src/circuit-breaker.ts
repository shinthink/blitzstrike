/** Circuit breaker — target health monitoring for no-babysitting scanning.
 *
 *  Tracks consecutive probe failures per target and opens a "circuit" after
 *  `limit` (default 5) consecutive timeouts/5xx, telling the agent to PAUSE
 *  instead of hammering an unresponsive target. The circuit auto-closes on the
 *  next successful probe. State is persisted at
 *  `$BLITZSTRIKE_HOME/circuit-breaker.json` (default ~/.blitzstrike/).
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const HOME_DIR = process.env.BLITZSTRIKE_HOME ?? join(homedir(), ".blitzstrike");
const STATE_PATH = join(HOME_DIR, "circuit-breaker.json");

interface TargetState {
  consecutive_failures: number;
  last_checked: string;
  circuit: "closed" | "open";
  opened_at?: string;
}

interface CircuitState {
  targets: Record<string, TargetState>;
}

function loadState(): CircuitState {
  try {
    if (existsSync(STATE_PATH)) return JSON.parse(readFileSync(STATE_PATH, "utf8")) as CircuitState;
  } catch {
    /* corrupt state -> start fresh */
  }
  return { targets: {} };
}

function saveState(s: CircuitState): void {
  try {
    mkdirSync(HOME_DIR, { recursive: true });
    writeFileSync(STATE_PATH, JSON.stringify(s, null, 2));
  } catch {
    /* best-effort persistence */
  }
}

export interface TargetHealthResult {
  target: string;
  healthy: boolean;
  status_code?: number;
  response_ms: number;
  consecutive_failures: number;
  circuit: "closed" | "open";
  advice: string;
}

export async function targetHealth(target: string, limit = 5): Promise<TargetHealthResult> {
  const state = loadState();
  const entry: TargetState = state.targets[target] ?? { consecutive_failures: 0, last_checked: "", circuit: "closed" };

  let healthy = false;
  let status: number | undefined;
  const t0 = Date.now();
  try {
    const res = await fetch(target, { method: "GET", redirect: "follow", signal: AbortSignal.timeout(10000), headers: { "User-Agent": "Mozilla/5.0 (compatible; BlitzStrike/2.4)" } });
    status = res.status;
    healthy = res.status < 500; // 2xx/3xx/4xx = reachable; 5xx = degraded
  } catch {
    healthy = false;
  }
  const responseMs = Date.now() - t0;

  if (healthy) {
    entry.consecutive_failures = 0;
    entry.circuit = "closed";
    entry.opened_at = undefined;
  } else {
    entry.consecutive_failures += 1;
    if (entry.consecutive_failures >= limit) {
      entry.circuit = "open";
      entry.opened_at = entry.opened_at ?? new Date().toISOString();
    }
  }
  entry.last_checked = new Date().toISOString();
  state.targets[target] = entry;
  saveState(state);

  const advice =
    entry.circuit === "open"
      ? `CIRCUIT OPEN after ${entry.consecutive_failures} consecutive failures — PAUSE this target and resume when it recovers (the circuit auto-closes on the next successful target_health probe).`
      : healthy
        ? `target responsive (HTTP ${status}) — safe to continue.`
        : `${entry.consecutive_failures}/${limit} consecutive failures — target degraded; consider slowing down or pausing before ${limit}.`;

  return { target, healthy, status_code: status, response_ms: responseMs, consecutive_failures: entry.consecutive_failures, circuit: entry.circuit, advice };
}

export function circuitStatus(): { targets: Array<TargetState & { target: string }>; open_count: number } {
  const state = loadState();
  const targets = Object.entries(state.targets).map(([target, s]) => ({ target, ...s }));
  targets.sort((a, b) => (b.consecutive_failures - a.consecutive_failures) || (a.circuit === "open" ? -1 : 1));
  return { targets, open_count: targets.filter((t) => t.circuit === "open").length };
}

export function resetCircuit(target: string): { target: string; reset: boolean } {
  const state = loadState();
  const existed = target in state.targets;
  delete state.targets[target];
  saveState(state);
  return { target, reset: existed };
}
