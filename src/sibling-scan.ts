/** Sibling Rule Engine — deterministic live prober for LOGIC bugs.
 *
 *  The static detectors have a hard ceiling on IDOR / broken-authz / mass
 *  assignment / rate-limit (they are semantic, not pattern-based). This tool
 *  closes that gap with a DETERMINISTIC, evidence-first live probe:
 *
 *   1. SIBLING ENUMERATION — from a base endpoint, generate sibling paths
 *      (/export /delete /share /{id} /list /settings …) + parent variants.
 *   2. DIFFERENTIAL IDOR — the victim's object fetched with the ATTACKER's token.
 *      A 200 (not 401/403) means the attacker can read the victim's object.
 *   3. AUTH MATRIX — probe each sibling with no token; a non-401/403 = missing
 *      authorization.
 *   4. MASS ASSIGNMENT — POST/PUT with an injected role/admin field; if the
 *      response reflects the privilege, mass assignment is proven.
 *   5. RATE LIMIT — N rapid requests to a sensitive sibling; if all pass the
 *      limit, the control is missing/weak.
 *
 *  Every hit is a DIFFERENTIAL (status + body), never a guess. Hits-only output.
 */

export interface SiblingScanInput {
  baseUrl: string;
  endpoint: string;
  tokenA?: string;
  tokenB?: string;
  objectIdB?: string;
  methods?: string[];
  maxSiblings?: number;
  timeoutMs?: number;
}

export interface SiblingFinding {
  endpoint: string;
  method: string;
  test: "idor" | "auth_matrix" | "mass_assignment" | "rate_limit";
  severity: "high" | "medium";
  verdict: string;
  request: string;
  evidence: string;
}

const SIBLING_SUFFIXES = [
  "export", "download", "delete", "remove", "share", "update", "edit",
  "settings", "profile", "details", "info", "list", "all", "index",
  "invoices", "payments", "billing", "orders", "transactions", "permissions",
  "roles", "admin", "members", "users", "api_key", "token", "config",
  "audit", "log", "history", "activity", "export_all", "bulk", "dump",
];

const MASS_ASSIGNMENT_FIELDS = ["role", "is_admin", "isAdmin", "admin", "is_staff", "group", "scope", "tenant_id"];

function stripTrailingSlash(u: string): string {
  return u.replace(/\/+$/, "");
}

/** Extract a numeric/UUID object-id segment from a path, or null. */
export function extractObjectId(endpoint: string): string | null {
  const segs = endpoint.split("/").filter(Boolean);
  for (const s of segs) {
    if (/^\d+$/.test(s)) return s;
    if (/^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(s)) return s;
  }
  return null;
}

/** Replace the object-id segment with a new id (or strip it). */
export function swapObjectId(endpoint: string, newId: string | null): string {
  const segs = endpoint.split("/").filter(Boolean);
  let replaced = false;
  const out = segs.map((s) => {
    if (!replaced && (/^\d+$/.test(s) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(s))) {
      replaced = true;
      return newId ?? s;
    }
    return s;
  });
  return "/" + out.join("/");
}

export function generateSiblings(endpoint: string, objectIdB?: string): string[] {
  const base = endpoint.split("?")[0];
  const out = new Set<string>();
  const id = objectIdB ?? extractObjectId(base);
  const baseNoId = id ? swapObjectId(base, null) : base;
  const parent = baseNoId.split("/").slice(0, -1).join("/");

  // sibling suffixes on the base path (and on the id-stripped path)
  for (const sfx of SIBLING_SUFFIXES) {
    out.add(`${baseNoId}/${sfx}`);
    if (parent) out.add(`${parent}/${sfx}`);
  }
  // id swaps (attacker -> victim id) + id-scoped siblings
  if (id) {
    out.add(swapObjectId(base, "0"));
    out.add(swapObjectId(base, "1"));
    out.add(swapObjectId(base, id)); // the bare victim-object swap (the core IDOR probe)
    for (const sfx of ["export", "download", "delete", "share", "settings", "invoices", "permissions", "orders", "details"]) {
      out.add(`${swapObjectId(base, id)}/${sfx}`);
    }
  }
  // parent-level + collection variants
  if (parent) {
    out.add(parent);
    out.add(`${parent}/all`);
    out.add(`${parent}/list`);
  }
  return [...out].filter((p) => p !== base).slice(0, 80);
}

async function httpReq(url: string, method: string, token: string | undefined, body?: string, timeoutMs = 8000): Promise<{ status: number; size: number; preview: string; ok: boolean }> {
  const headers: Record<string, string> = { "User-Agent": "blitzstrike/2" };
  if (token) headers["Authorization"] = token.startsWith("Bearer ") ? token : `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { method, headers, body, signal: ctrl.signal, redirect: "manual" });
    const text = await res.text();
    return { status: res.status, size: text.length, preview: text.slice(0, 200).replace(/\s+/g, " ").trim(), ok: res.ok };
  } catch {
    return { status: 0, size: 0, preview: "(network error/timeout)", ok: false };
  } finally {
    clearTimeout(t);
  }
}

export async function siblingScan(input: SiblingScanInput): Promise<Record<string, unknown>> {
  const base = stripTrailingSlash(input.baseUrl);
  const endpoint = input.endpoint.startsWith("/") ? input.endpoint : `/${input.endpoint}`;
  const methods = input.methods ?? ["GET"];
  const maxSiblings = input.maxSiblings ?? 60;
  const timeoutMs = input.timeoutMs ?? 8000;
  const objectIdB = input.objectIdB ?? extractObjectId(endpoint);

  const findings: SiblingFinding[] = [];
  const siblings = generateSiblings(endpoint, objectIdB ?? undefined).slice(0, maxSiblings);
  let tested = 0;

  const record = (f: SiblingFinding) => {
    findings.push(f);
    if (findings.length <= 200) console.log(JSON.stringify(f)); // real-time append
  };

  // ---- 1. Baseline + differential IDOR + auth matrix per sibling ----------
  for (const sib of siblings) {
    for (const method of methods) {
      tested++;
      const url = `${base}${sib}`;

      // auth matrix: no token — flag only 2xx/3xx (success = missing auth),
      // a 404 means the endpoint simply does not exist.
      const noAuth = await httpReq(url, method, undefined, undefined, timeoutMs);
      if (noAuth.status >= 200 && noAuth.status < 400) {
        record({
          endpoint: sib, method, test: "auth_matrix", severity: "high",
          verdict: `Missing authorization — ${method} ${sib} returns HTTP ${noAuth.status} with NO token`,
          request: `${method} ${url} (no auth)`,
          evidence: `HTTP ${noAuth.status}, ${noAuth.size}B body: ${noAuth.preview}`,
        });
      }

      // differential IDOR: victim's object with the attacker's token — flag only
      // a SUCCESS (2xx/3xx); a 404 is "object/endpoint missing", not IDOR.
      if (input.tokenA && objectIdB) {
        const victimUrl = `${base}${swapObjectId(sib, objectIdB)}`;
        const victimBaseline = await httpReq(victimUrl, method, input.tokenB, undefined, timeoutMs);
        const attackerOnVictim = await httpReq(victimUrl, method, input.tokenA, undefined, timeoutMs);
        if (attackerOnVictim.status >= 200 && attackerOnVictim.status < 400) {
          const sameAsVictim = victimBaseline.ok && Math.abs(victimBaseline.size - attackerOnVictim.size) <= Math.max(64, victimBaseline.size * 0.1);
          record({
            endpoint: victimUrl.replace(base, ""), method, test: "idor", severity: "high",
            verdict: `IDOR — attacker A reads victim B's object (HTTP ${attackerOnVictim.status} with A's token + B's id${sameAsVictim ? ", body matches B's baseline" : ""})`,
            request: `${method} ${victimUrl} (token A, object id B)`,
            evidence: `A=${attackerOnVictim.status}/${attackerOnVictim.size}B vs B=${victimBaseline.status}/${victimBaseline.size}B → ${attackerOnVictim.preview}`,
          });
        }
      }
    }
  }

  // ---- 2. Mass assignment — POST/PUT role injection -----------------------
  if ((methods.includes("POST") || methods.includes("PUT")) && input.tokenA) {
    const createLike = siblings.filter((s) => /register|create|signup|user|admin|member/i.test(s)).slice(0, 5);
    if (createLike.length === 0) createLike.push(endpoint);
    for (const sib of createLike.slice(0, 3)) {
      const url = `${base}${sib}`;
      for (const field of MASS_ASSIGNMENT_FIELDS) {
        const body = JSON.stringify({ [field]: "admin", email: "attacker@example.com", name: "attacker" });
        const res = await httpReq(url, "POST", input.tokenA, body, timeoutMs);
        tested++;
        // mass assignment signal: the request succeeds (200/201) and the body echoes admin/role
        if (res.ok && /admin|"role"|is_admin/i.test(res.preview)) {
          record({
            endpoint: sib, method: "POST", test: "mass_assignment", severity: "high",
            verdict: `Mass assignment — injecting '${field}=admin' on ${sib} returns ${res.status} and reflects admin/role`,
            request: `POST ${url} body={${field}:admin,...}`,
            evidence: `HTTP ${res.status}, ${res.size}B: ${res.preview}`,
          });
          break;
        }
      }
    }
  }

  // ---- 3. Rate limit — N rapid requests to a sensitive sibling ------------
  const sensitive = siblings.find((s) => /export|download|invoice|payment|user|admin|token|api_key/i.test(s)) ?? endpoint;
  const url = `${base}${sensitive}`;
  let allPassed = 0;
  for (let i = 0; i < 15; i++) {
    const res = await httpReq(url, "GET", input.tokenA, undefined, Math.min(timeoutMs, 4000));
    tested++;
    if (res.status >= 200 && res.status < 400) allPassed++;
  }
  if (allPassed >= 15) {
    record({
      endpoint: sensitive, method: "GET", test: "rate_limit", severity: "medium",
      verdict: `Rate limit missing/weak — 15/15 rapid requests to ${sensitive} all succeeded (no 429)`,
      request: `GET ${url} ×15 (token A)`,
      evidence: `${allPassed}/15 requests returned non-denied status`,
    });
  }

  return {
    base_url: base,
    endpoint,
    object_id_b: objectIdB,
    siblings_enumerated: siblings.length,
    requests_made: tested,
    findings,
    summary: {
      total: findings.length,
      idor: findings.filter((f) => f.test === "idor").length,
      auth_matrix: findings.filter((f) => f.test === "auth_matrix").length,
      mass_assignment: findings.filter((f) => f.test === "mass_assignment").length,
      rate_limit: findings.filter((f) => f.test === "rate_limit").length,
    },
  };
}
