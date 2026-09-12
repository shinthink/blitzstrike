---
name: api-security-test
description: Use when testing a REST or GraphQL API specifically — broken object-level authorization (BOLA/IDOR), mass assignment, excessive data exposure, missing rate limiting, and GraphQL-specific risks like introspection exposure and query depth abuse. Pulls from OWASP API Security Top 10 rather than the general web OWASP Top 10.
---

# API security test

APIs fail differently than server-rendered web apps — mostly around authorization granularity and data exposure, since there's no UI hiding the raw response shape.

## Prerequisites

- `ffuf` (endpoint/parameter fuzzing), any HTTP client, GraphQL introspection query if applicable
- The API's schema/spec if available (OpenAPI/Swagger JSON, GraphQL SDL) — massively speeds up coverage

## Workflow

1. **Pull the full endpoint surface.** If OpenAPI/Swagger is exposed (`/swagger.json`, `/openapi.json`, `/api-docs`), fetch it — it's a complete map of every endpoint, param, and expected type. If not, rely on `attack-surface-recon`'s crawled endpoints plus client-side JS analysis for undocumented routes.

2. **BOLA/IDOR (the #1 API vuln class):** for every endpoint that takes a resource ID, systematically test cross-user/cross-tenant access exactly as in `web-app-pentest` step 5, but be exhaustive here — APIs typically have far more ID-addressable resources than a web UI exposes. Script it rather than testing by hand if there are more than a handful of endpoints:
   ```bash
   # pseudo-pattern: replay each authenticated request with a different user's token/session
   for endpoint in $(cat findings/endpoints.txt); do
     curl -s -H "Authorization: Bearer $USER_A_TOKEN" "$endpoint" -o a.json
     curl -s -H "Authorization: Bearer $USER_B_TOKEN" "$endpoint" -o b.json
     # flag if user B's token can read/write user A's resource
   done
   ```

3. **Mass assignment:** for every write endpoint (POST/PATCH/PUT), send extra unexpected fields in the body (`"role": "admin"`, `"isVerified": true`, `"price": 0`) and check if the API applies them instead of silently ignoring. This is a critical finding when it lets a normal user set privileged fields.

4. **Excessive data exposure:** compare the API response shape against what the frontend actually renders. APIs frequently return full internal objects (password hashes, internal flags, other users' PII in a list response) that the client just doesn't display — the data is still exposed to anyone inspecting the raw response.

5. **Rate limiting / resource exhaustion:** hit an auth endpoint (login, OTP verify, password reset) and any expensive query endpoint with rapid repeated requests. No 429/throttling after a reasonable burst is a finding — flag brute-force exposure on auth endpoints specifically as high severity.

6. **GraphQL-specific (if applicable):**
   - Check if introspection is enabled in production: `{"query": "{__schema{types{name}}}"}`. Enabled introspection on a public prod endpoint is a low-to-medium finding (info disclosure) but massively speeds up further testing — use it if available.
   - Test for missing query depth/complexity limits by sending a deeply nested query — an unbounded response or timeout indicates a DoS vector.
   - Test field-level authorization separately from endpoint-level — GraphQL resolvers commonly forget to re-check auth on nested fields that REST equivalents do check.

7. **API versioning gaps:** if `/v2/` exists, check whether `/v1/` is still live and whether it lacks fixes/checks that v2 has — deprecated-but-reachable versions are a common bypass.

## Output

Per finding: endpoint, method, auth context used, exact request/response pair proving the issue, severity per OWASP API Security Top 10 category (e.g. `API1:2023 - BOLA`). Feed into `findings-report`.

## Notes

- Always test with at least two distinct user accounts/tenants — most of this skill's highest-value findings are invisible testing with a single account.
- If the API sits behind `auth-session-security`-relevant tokens (JWT, OAuth), run that skill first — a token vulnerability there often unlocks everything here.
