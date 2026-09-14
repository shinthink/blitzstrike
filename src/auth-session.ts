/** Authenticated session — HTTP form login → session cookie/token extraction.
 *
 *  Level 1/2 authenticated scanning: POST credentials to a login endpoint, extract
 *  the resulting session cookie (Set-Cookie) + any access/refresh token (JWT in the
 *  body or JSON), and return a reusable session context so the agent can drive
 *  authenticated scans (sibling_scan token_a, nuclei_scan headers, etc.).
 */
import { redactSecrets } from "./evidence.js";

export interface AuthLoginResult {
  ok: boolean;
  login_url: string;
  status?: number;
  cookies: Array<{ name: string; value: string }>;
  tokens: Array<{ name: string; value: string }>;
  detail: string;
}

function parseCookies(setCookie: string | null): Array<{ name: string; value: string }> {
  if (!setCookie) return [];
  const out: Array<{ name: string; value: string }> = [];
  for (const part of setCookie.split(/,(?=\s*[A-Za-z0-9_-]+=)/)) {
    const m = part.trim().match(/^([^=;]+)=([^;]*)/);
    if (m) out.push({ name: m[1].trim(), value: m[2].trim() });
  }
  return out;
}

function extractTokens(body: string): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = [];
  for (const re of [/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, /"access_token"\s*:\s*"([^"]+)"/g, /"token"\s*:\s*"([^"]+)"/g, /"refresh_token"\s*:\s*"([^"]+)"/g]) {
    for (const m of body.matchAll(re)) {
      const v = m[1] ?? m[0];
      if (v && !out.some((t) => t.value === v)) out.push({ name: v.startsWith("eyJ") ? "jwt" : "token", value: v });
    }
  }
  return out;
}

export async function authLogin(
  loginUrl: string,
  username: string,
  password: string,
  opts?: { user_field?: string; pass_field?: string; extra?: Record<string, string>; totp?: string; totp_field?: string },
): Promise<AuthLoginResult> {
  const userField = opts?.user_field ?? "username";
  const passField = opts?.pass_field ?? "password";

  const form = new URLSearchParams({ [userField]: username, [passField]: password, ...(opts?.extra ?? {}) });
  if (opts?.totp) form.set(opts?.totp_field ?? "code", opts.totp);

  let res: Response;
  try {
    res = await fetch(loginUrl, {
      method: "POST",
      redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (compatible; BlitzStrike/2.4)" },
      body: form.toString(),
    });
  } catch (e) {
    return { ok: false, login_url: loginUrl, cookies: [], tokens: [], detail: `login request failed: ${e instanceof Error ? e.message : String(e)}` };
  }

  const body = await res.text();
  const cookies = parseCookies(res.headers.get("set-cookie"));
  const tokens = extractTokens(body);
  const ok = res.status < 400 && (cookies.length > 0 || tokens.length > 0);

  return {
    ok,
    login_url: loginUrl,
    status: res.status,
    cookies: cookies.map((c) => ({ name: c.name, value: redactSecrets(c.value) })),
    tokens: tokens.map((t) => ({ name: t.name, value: redactSecrets(t.value) })),
    detail: ok
      ? `authenticated (HTTP ${res.status}) — ${cookies.length} session cookie(s), ${tokens.length} token(s) captured for authenticated scanning`
      : `login failed (HTTP ${res.status}) — no session cookie or token captured; check credentials/fields or use browser_agent for a JS login flow`,
  };
}
