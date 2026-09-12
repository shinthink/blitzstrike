/** Route-confusion & dispatch-abuse detection.
 *
 * A distinct vulnerability class from source→sink taint: the routing/dispatch
 * layer lets an attacker reach an unintended handler, or controls WHICH handler
 * runs, bypassing authorization. Signals:
 *
 *   - dynamic dispatch     — user-controlled callback/route (`call_user_func`,
 *                            `forward`, `dispatch`, `resolve_route`).
 *   - dynamic method call  — `$obj->$method()` / `$class::$method()`.
 *   - dynamic include      — `include`/`require` of a variable (LFI via route).
 *   - batch forwarding     — a loop over sub-requests that forwards to inner
 *                            handlers (no per-route auth re-check).
 *   - route normalization  — route matching without path normalization
 *                            (strtolower/rtrim/urldecode/canonicalization),
 *                            enabling route desync.
 */

export type RouteConfusionType =
  | "dynamic_dispatch"
  | "dynamic_method_call"
  | "dynamic_include"
  | "batch_forwarding"
  | "route_normalization_gap";

export interface RouteFinding {
  file: string;
  line: number;
  type: RouteConfusionType;
  category: string;
  severity: "high" | "medium" | "low";
  evidence: string;
  detail: string;
}

const SOURCE_TOKENS = /\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\$request->|\$req->|request\.(get|input|query|post)|getParameter\(|req\.(query|body|params)/;

function lines(code: string): string[] {
  return code.split("\n");
}

function lineNo(code: string, pos: number): number {
  let n = 1;
  for (let i = 0; i < pos; i++) if (code.charCodeAt(i) === 10) n++;
  return n;
}

/** Is a variable on the line/statement fed by user input? (cheap local heuristic) */
function userControlled(scope: string): boolean {
  return SOURCE_TOKENS.test(scope);
}

const DYNAMIC_DISPATCH_RE = /\b(call_user_func|call_user_func_array|forward|dispatch|resolve_route|invoke)\s*\(\s*(\$|\[)/gi;
const DYNAMIC_METHOD_RE = /(->|::)\s*\$[A-Za-z_]/g;
const BATCH_LOOP_RE = /\bforeach\s*\([^)]*(requests|batch|sub_requests|operations)\b/gi;
const ROUTE_MATCH_RE = /\b(preg_match|preg_match_all|strpos|stripos|str_contains)\s*\(/i;

/** Normalization helpers whose ABSENCE on a route match suggests a desync gap. */
const NORMALIZERS = /\b(strtolower|strtoupper|rtrim|urldecode|rawurldecode|parse_url|normalize|canonical)\b/i;

function detectDynamicDispatch(code: string, file: string, out: RouteFinding[]): void {
  const ls = lines(code);
  DYNAMIC_DISPATCH_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = DYNAMIC_DISPATCH_RE.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    const scope = ls.slice(Math.max(0, ln - 4), ln).join("\n");
    if (!userControlled(l) && !userControlled(scope)) continue;
    out.push({
      file,
      line: ln,
      type: "dynamic_dispatch",
      category: "Route confusion (user-controlled dispatch)",
      severity: "high",
      evidence: l.trim(),
      detail: `\`${m[1]}()\` invoked with an attacker-controlled callback/route — the request selects the handler.`,
    });
  }
}

function detectDynamicMethod(code: string, file: string, out: RouteFinding[]): void {
  const ls = lines(code);
  DYNAMIC_METHOD_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = DYNAMIC_METHOD_RE.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    // Scope: look a few lines up for a source feeding the method/class var.
    const scope = ls.slice(Math.max(0, ln - 4), ln).join("\n");
    if (!userControlled(l) && !userControlled(scope)) continue;
    out.push({
      file,
      line: ln,
      type: "dynamic_method_call",
      category: "Route confusion (dynamic method dispatch)",
      severity: "high",
      evidence: l.trim(),
      detail: "Dynamic method/static call `" + m[1] + "$var()` — the invoked symbol is attacker-influenced.",
    });
  }
}

function detectDynamicInclude(code: string, file: string, out: RouteFinding[]): void {
  const ls = lines(code);
  const re = /\b(include|require)(_once)?\s*\(\s*(\$[A-Za-z_]\w*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    const scope = ls.slice(Math.max(0, ln - 4), ln).join("\n");
    if (!userControlled(l) && !userControlled(scope)) continue;
    out.push({
      file,
      line: ln,
      type: "dynamic_include",
      category: "Route confusion (dynamic file include)",
      severity: "high",
      evidence: l.trim(),
      detail: `\`${m[1]}(…)\` of a variable — potential LFI/RCE when the path is attacker-controlled.`,
    });
  }
}

function detectBatchForwarding(code: string, file: string, out: RouteFinding[]): void {
  BATCH_LOOP_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = BATCH_LOOP_RE.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    // Find the loop body (up to ~8 lines) for a forwarding call.
    const body = lines(code).slice(ln, ln + 8).join("\n");
    const forwards = /\b(call_user_func|forward|dispatch|resolve_route|invoke|handle|route)\s*\(/i.test(body);
    if (!forwards) continue;
    const rechecks = /\b(current_user_can|permission_callback|check_ajax_referer|authorize|authorise|is_user_logged_in)\b/i.test(body);
    out.push({
      file,
      line: ln,
      type: "batch_forwarding",
      category: "Route confusion (batch/proxy forwarding)",
      severity: rechecks ? "medium" : "high",
      evidence: lines(code)[ln - 1]?.trim() ?? "",
      detail: rechecks
        ? "Batch/proxy loop forwards to inner handlers — auth is re-checked in scope, but verify it applies per-route."
        : "Batch/proxy loop forwards to inner handlers with no per-route authorization re-check — an attacker may reach a protected handler.",
    });
  }
}

function detectRouteNormalization(code: string, file: string, out: RouteFinding[]): void {
  const ls = lines(code);
  for (let i = 0; i < ls.length; i++) {
    const l = ls[i];
    if (!ROUTE_MATCH_RE.test(l)) continue;
    // The normalization gap is only meaningful if the matched subject is user input.
    const scope = ls.slice(Math.max(0, i - 3), i + 1).join("\n");
    if (!userControlled(scope)) continue;
    if (NORMALIZERS.test(l) || NORMALIZERS.test(scope)) continue;
    out.push({
      file,
      line: i + 1,
      type: "route_normalization_gap",
      category: "Route confusion (missing path normalization)",
      severity: "medium",
      evidence: l.trim(),
      detail: "Route matched against user input without visible normalization (strtolower/rtrim/urldecode) — route desync possible.",
    });
  }
}

/** Run all route-confusion detectors over one file's source. */
export function detectRouteConfusion(code: string, file: string): RouteFinding[] {
  const out: RouteFinding[] = [];
  detectDynamicDispatch(code, file, out);
  detectDynamicMethod(code, file, out);
  detectDynamicInclude(code, file, out);
  detectBatchForwarding(code, file, out);
  detectRouteNormalization(code, file, out);
  return out;
}
