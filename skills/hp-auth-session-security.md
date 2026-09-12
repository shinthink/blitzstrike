---
name: auth-session-security
description: Use when testing authentication and session handling specifically — JWT vulnerabilities, session fixation, cookie flags, OAuth/SSO misconfiguration, password reset flow flaws, and MFA bypass. Run before api-security-test and web-app-pentest when the app is meaningfully authenticated, since a broken auth layer undermines every access-control finding downstream.
---

# Auth & session security

## Prerequisites

- `jwt_tool` if the app uses JWTs
- Browser devtools or a proxy to inspect cookies/headers directly

## Workflow

1. **JWT testing** (if the app issues JWTs):
   ```bash
   jwt_tool <token> -M at   # runs all known attack modes: alg confusion, none-alg, key confusion, etc.
   ```
   Manually confirm the highest-value checks:
   - **`alg: none`** — strip the signature, set `alg` to `none`, see if the server still accepts it.
   - **Algorithm confusion (RS256→HS256)** — if the server uses RS256 (asymmetric), try re-signing the token as HS256 using the public key as the HMAC secret; servers that don't pin the expected algorithm will verify it.
   - **Weak/guessable HMAC secret** — if HS256, attempt to crack the secret offline (`hashcat` / `jwt_tool`'s cracking mode) against common wordlists.
   - **Missing/loose expiration** — check `exp` is present, enforced, and not absurdly long-lived. Test using an expired token directly against the API.
   - **Sensitive data in the payload** — JWTs are base64, not encrypted; decode the payload and check for PII, internal roles, or secrets that shouldn't be client-readable.

2. **Session cookie hygiene** — inspect `Set-Cookie` headers on login:
   - `HttpOnly` present (prevents JS/XSS from reading the session cookie)
   - `Secure` present (cookie never sent over plain HTTP)
   - `SameSite=Lax` or `Strict` (CSRF mitigation)
   - Session token has real entropy (long, random) — not a sequential ID or predictable value
   - Session token rotates on login/privilege change (test: capture a pre-login session ID, log in, confirm the ID changed — a static ID across the login boundary is session fixation)

3. **Password reset flow** — walk it end to end:
   - Reset token is single-use and expires quickly (test replay after use, and after a time delay)
   - Reset token isn't predictable/sequential and has sufficient entropy
   - The flow doesn't leak whether an email/username exists (compare response for valid vs. invalid account — timing and message differences both count)
   - Old sessions are invalidated after a password reset (test: hold an active session, reset the password from another session, confirm the first session is killed)

4. **MFA, if present:**
   - Backup/recovery codes have real entropy and are single-use
   - MFA can't be bypassed by directly hitting the post-auth endpoint/redirect without completing the second factor
   - No rate limit gap that allows brute-forcing the OTP (6-digit OTP with no throttling is crackable in minutes)

5. **OAuth/SSO, if present:**
   - `redirect_uri` is validated against an exact allowlist, not just a prefix/substring match (open redirect → token theft)
   - `state` parameter is present, unpredictable, and validated on callback (CSRF protection for the OAuth flow)
   - Access tokens aren't leaked via `Referer` header when the app navigates away from a page containing them in the URL

## Output

Per finding: which mechanism (JWT/cookie/reset/MFA/OAuth), the specific check that failed, proof (request/response or decoded token), severity. A broken JWT signature check or session-fixation bug is critical — it invalidates access-control assumptions everywhere else in the app, so flag it as a blocking finding, not just one item in a list.

## Notes

- This skill's findings compound with `api-security-test` and `web-app-pentest` — a JWT alg-confusion bug means every IDOR test elsewhere in the app should be re-run assuming full auth bypass is possible.
