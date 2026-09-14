/** Deterministic Identity Token Forgeability Analyzer — JWT crypto oracle.
 *
 *  A JSON Web Token is `header.payload.signature`, each base64url. The signature
 *  is the ONLY thing stopping an attacker from editing the payload (identity /
 *  role) and replaying it. This module DETERMINISTICALLY parses a token and
 *  enumerates the forge vectors — alg:none, missing signature, RS256→HS256 key
 *  confusion, kid header injection, weak HS secret (brute-forced against a
 *  wordlist), missing expiry — turning a "how to forge JWT" reference into a
 *  verifiable, evidence-first verdict.
 */
import { createHmac } from "node:crypto";
import { sha256 } from "./evidence.js";

export interface JwtDecoded {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
  segments: number;
}

/** Base64url-decode a JWT segment to a UTF-8 string. */
function b64urlDecode(seg: string): string {
  return Buffer.from(seg.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
}

/** Split + decode a JWT into header/payload/signature (null if malformed). */
export function decodeJwt(token: string): JwtDecoded | null {
  const parts = String(token).trim().split(".");
  if (parts.length < 2) return null;
  try {
    const header = JSON.parse(b64urlDecode(parts[0]));
    const payload = JSON.parse(b64urlDecode(parts[1]));
    return { header, payload, signature: parts[2] ?? "", segments: parts.length };
  } catch {
    return null;
  }
}

export interface JwtFinding {
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  detail: string;
  forge?: string;
}

/** Deterministic forgeability analysis of a JWT (pure, testable). */
export function analyzeJwt(token: string, opts: { wordlist?: string[] } = {}): Record<string, unknown> {
  const decoded = decodeJwt(token);
  if (!decoded) return { error: "not a parseable JWT", token_preview: String(token).slice(0, 24) };

  const { header, payload, signature, segments } = decoded;
  const alg = String(header.alg ?? "");
  const findings: JwtFinding[] = [];

  // 1. alg:none (or case variant).
  if (/^none$/i.test(alg)) {
    findings.push({
      type: "alg_none", severity: "critical",
      detail: `the token declares alg="${alg}" — a verifier that trusts the alg header skips signature verification entirely.`,
      forge: "set header alg:none, edit payload (role:admin / another sub), drop the signature, keep the trailing dot.",
    });
  }

  // 2. Missing signature segment.
  if (segments === 2) {
    findings.push({
      type: "no_signature", severity: "high",
      detail: "the token has no signature segment — if the server accepts it, the payload is directly editable.",
      forge: "edit the payload segment and replay without a signature.",
    });
  }

  // 3. Asymmetric alg → RS256→HS256 key confusion.
  if (/^(RS|ES|PS)\d+$/i.test(alg)) {
    findings.push({
      type: "key_confusion", severity: "high",
      detail: `asymmetric alg ${alg} — if the verifier accepts HS256, the PUBLIC key can be reused as the HMAC secret (key confusion).`,
      forge: "re-sign an edited payload with HS256 using the RSA public key (from /jwks.json or /.well-known/jwks.json) as the HMAC secret.",
    });
  }

  // 4. kid header injection.
  if (header.kid !== undefined) {
    findings.push({
      type: "kid_header", severity: "medium",
      detail: `kid header present ("${String(header.kid).slice(0, 40)}") — if the verifier loads the key from a file/DB/URL named by kid, this is a path-traversal / SQLi / SSRF vector.`,
      forge: 'try kid="../../../../dev/null" (empty key) or a URL you control.',
    });
  }

  // 5. jku / x5u header (remote key fetch).
  if (header.jku !== undefined || header.x5u !== undefined) {
    findings.push({
      type: "remote_key_header", severity: "medium",
      detail: "jku/x5u header present — the verifier may fetch the verification key from a URL the token controls (SSRF / key substitution).",
      forge: "host a JWKS at a URL you control and point jku at it.",
    });
  }

  // 6. Weak HS secret (brute force against a wordlist).
  if (/^HS\d+$/i.test(alg) && signature && opts.wordlist && opts.wordlist.length > 0) {
    const data = `${token.split(".")[0]}.${token.split(".")[1]}`;
    for (const w of opts.wordlist.slice(0, 10000)) {
      const sig = createHmac("sha256", w).update(data).digest("base64url");
      if (sig === signature) {
        findings.push({
          type: "weak_secret", severity: "critical",
          detail: `the HS256 secret is a guessable value: "${w}" — the token is directly forgeable.`,
          forge: `sign any payload with HS256 using secret "${w}".`,
        });
        break;
      }
    }
  }

  // 7. Missing expiry.
  if (payload.exp === undefined && payload.iat === undefined) {
    findings.push({
      type: "no_expiry", severity: "low",
      detail: "no exp/iat claim — the token never expires (unbounded replay window).",
    });
  }

  // 8. Sensitive / privilege-bearing claims.
  const sensitiveKeys = Object.keys(payload).filter((k) => /role|admin|is_admin|permission|scope|privilege|sub|user_id|email|is_staff/i.test(k));
  const sensitiveClaims: Record<string, unknown> = {};
  for (const k of sensitiveKeys) sensitiveClaims[k] = payload[k];

  const forgeable = findings.some((f) => f.severity === "critical" || f.severity === "high");

  return {
    alg,
    segments,
    forgeable,
    findings,
    sensitive_claims: sensitiveClaims,
    header,
    payload,
    interpretation: "a finding is a forge VECTOR, not proof — confirm by forging + replaying against the live verifier before reporting.",
  };
}

/** Produce an alg:none token (strip signature) for verification. */
export function forgeAlgNone(token: string, payload: Record<string, unknown>): string {
  const decoded = decodeJwt(token);
  if (!decoded) return "";
  const header = { ...decoded.header, alg: "none" };
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64(header)}.${b64(payload)}.`;
}

/** Stable token fingerprint for evidence tagging (does not leak secrets). */
export function tokenFingerprint(token: string): string {
  return sha256(String(token)).slice(0, 16);
}
