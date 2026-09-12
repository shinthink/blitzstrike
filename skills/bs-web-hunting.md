---
name: web-hunting
description: Use when the target is a LIVE web application or API and you are bug hunting — advanced, beyond basic OWASP. Deep recon, advanced injection (HTTP request smuggling, cache attacks, race conditions, SSRF bypass), advanced auth (JWT/OAuth), client-side attacks, and the chain mindset. Every finding still passes marker + negative control.
---

# Advanced Web Bug Hunting (live target)

Professional bug hunting is not a checklist — it is **recon depth → advanced
classes → chaining**. Basic SQLi/XSS is table stakes; the bugs that matter are
the ones basic scanners miss. Hunt those.

## Mindset

- **The surface is bigger than you think.** JS bundles, source maps, hidden
  endpoints, non-standard ports, versioned APIs, and callback URLs all leak
  attack surface that a naive crawl misses.
- **Every finding chains.** A cache poisoning is only interesting because it
  becomes stored XSS; an open redirect matters because it steals an OAuth
  token. Always ask "what does this escalate into?"
- **Bypass, don't give up.** A WAF/sanitizer/filter is a puzzle, not a wall —
  `bypass_lookup(defense)` for the concrete evasions.
- **Still anti-FP.** None of the below is reported without `strike_verify`
  (marker + negative control). Advanced ≠ speculative.

## Phase 1 — Deep recon (map the real surface)

1. **JS static analysis** — pull every `<script src>`; grep for endpoints,
   `/api/`, tokens, keys, subdomains, and source-map refs. Download `.map`
   files to recover original source + hidden routes.
2. **Parameter mining** — `arjun` / `x8` / `ParamMiner` for hidden params;
   fuzz common ones (`?debug=1`, `?backup=1`, `?admin=1`, `?source=1`).
3. **Versioned/legacy APIs** — `/api/v1` vs `/api/v2` vs `/api/v3`, and
   deprecated paths (`/old`, `/backup`, `/legacy`, `/dev`, `/staging`).
4. **Exposed config** — `/.git/`, `/.env`, `/.svn/`, `/backup.zip`, `/wp-config.php.bak`,
   `/.DS_Store`, `/composer.json`, `/package.json`, `/actuator/`, `/debug/`.
5. **WAF fingerprint** — `detect_waf` before probing; a WAF changes the whole
   payload strategy (encoding/case/chunked vs direct).
6. **Non-standard ports + virtual hosts** — `live_recon` port scan; test
   `X-Forwarded-Host`, `Host`, and alternate vhosts — they often route to
   admin/internal apps.

## Phase 2 — Advanced injection (beyond the basics)

### HTTP request smuggling
- Test CL.TE, TE.CL, TE.TE on every endpoint behind a front-end/back-end pair.
- The prize: smuggled requests that poison the next user's request → session
  hijack, cache poisoning, or WAF bypass.
- `bypass_lookup(waf)` + `read_payload(request-smuggling)`; verify with a
  timing marker (the smuggled request's response lands on YOUR request).

### Web cache poisoning / deception
- Find **unkeyed headers** that reflect into the response (`X-Forwarded-Host`,
  `X-Forwarded-Scheme`, `X-Original-URL`, `X-Host`, custom `X-*`).
- Poison the cache with a payload in an unkeyed header → stored on the shared
  response → stored XSS for every visitor. Verify the cache is actually shared
  (hit it from a second request + confirm the reflected payload persists).

### SSRF — the bypass ladder
- Basic `127.0.0.1`/`localhost` blocked? Escalate the ladder:
  `127.1`, `0`, `0x7f000001`, `2130706433`, `017700000001`, `[::1]`,
  `127.0.0.1.nip.io`, DNS rebinding, `http://127.0.0.1:80@evil/`, double-URL-encode.
- Scheme tricks: `gopher://`, `dict://`, `file://`, `http://` to internal ports.
- Redirect bypass: an allow-listed host that 302s to an internal address.
- DNS-rebinding vs safe-url checks: a "safe" wrapper that resolves the hostname
  once to validate and again to connect (e.g. `wp_safe_remote_*`) is rebinding-
  bypassable — the name resolves to an allowed IP at check time and an internal
  IP at request time.
- The prize: cloud metadata (`169.254.169.254`), Redis/Postgres, internal admin.
  `ap-ssrf-cloud-metadata` skill has the metadata endpoints.

### Race conditions
- TOCTOU: spend-a-coupon-twice, withdraw-twice, redeem-twice — fire parallel
  requests (single-packet attack via HTTP/2) and check for the double effect.
- Session/register races, file-upload races (upload → check → replace).

### Deserialization → RCE
- Spot serialized blobs in params/cookies (PHP `O:`, Java `rO0AB`, .NET,
  `pickle`). Build a gadget chain with `ysoserial`/`PHPGGC` (`tool_lookup`).
- Verify with a marker command (`id`/`touch /tmp/<marker>`) via a callback —
  never claim RCE without the command actually firing.

### Server-side template injection
- Probe with `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}` — the marker is the
  evaluated arithmetic (`49`), the control is a benign literal.
- Filter bypass: nested attributes, `|attr`, string concat, `__mro__`/`__subclasses__`
  (Python), `T(java.lang.Runtime)` (Java) for RCE.

### Prototype pollution
- Client-side: merge of `location.hash`/`URLSearchParams` into an object →
  `__proto__`/`constructor.prototype` → XSS/gadget.
- Server-side: `Object.assign`/`_.merge`/`lodash.merge` of request body → RCE
  via polluted options (child_process, template, etc.).

## Phase 3 — Auth & session (advanced)

### JWT
- `alg:none`; HS256/RS256 **key confusion** (sign with the public key as HMAC);
  `kid` injection (path traversal / SQLi in `kid`); `jku`/`x5u` to an
  attacker-controlled key URL.
- Weak secret → crack with `jwt_tool`/`hashcat` (`tool_lookup(jwt_tool)`).

### OAuth / SSO
- `redirect_uri` confusion (open redirect, path/param variations, missing
  `state`), `state` leakage → CSRF on the callback, code/token theft.
- PKCE downgrade; client-secret leak; `response_type` tampering.

### Host header injection
- Password-reset poisoning: `Host: attacker.com` in the reset link → the token
  is emailed to your host.
- Routing bypass + cache poisoning via `Host`/`X-Forwarded-Host`.

## Phase 4 — Client-side (advanced)

### CORS
- `Access-Control-Allow-Origin: null`, reflection of `Origin`, trusted-subdomain
  takeover, missing `Vary: Origin` (cache leaks cross-origin responses),
  `Access-Control-Allow-Credentials: true` + wildcard.

### CSP bypass
- Nonce reuse, `unsafe-inline`, JSONP endpoints, `script-src` whitelist that
  allows a takeover-able domain, dangling markup injection.

### Open redirect → impact
- `//evil.com`, `https://trusted.com@evil.com`, `/%2f%2fevil.com`, backslash,
  `javascript:` (rare) — then chain to OAuth token theft or credential
  phishing (redirect to a lookalike login).

## Phase 5 — API & modern stacks

### GraphQL
- Introspection dump → full schema. Aliases + batching to bypass rate limits
  and force deep recursion (DoS). Field/authorization bypass: query a field the
  UI hides. Batching to test IDOR across objects.

### WebSocket
- Cross-site WebSocket hijacking (no `Origin` check), message smuggling,
  authorization on `connect` but not per-message.

### IDOR / BOLA (advanced)
- Not just `?id=1` → `?id=2`: parameterized references (`/users/me` →
  `/users/<guid>`), mass assignment on PATCH, API version confusion, and
  UUIDv4 vs sequential ID (a guessable ID is the bug). Verify by reading
  another user's object across roles — never by "it returned 200".

## Phase 6 — The chain mindset

A single finding is rarely the end. For each confirmed finding, enumerate the
follow-ups (`list_chains` + `chain_links`):

- **Cache poisoning → stored XSS** (poison → every visitor gets your payload).
- **Open redirect → OAuth token theft** (redirect steals the authorization code).
- **Request smuggling → session hijack** (smuggled request captures the next user's session).
- **SSRF → cloud metadata → credential theft → lateral movement**.
- **Host header injection → password reset → account takeover**.
- **Subdomain takeover → trusted-origin CORS/XSS on the parent**.

Trace the full composition — that is the difference between a script-kiddie
finding and a professional bug.

## Verify (anti-FP still applies)

Every hypothesis above becomes a finding only after `strike_verify` (unique
marker + negative control + baseline). "This might be exploitable" is a
hypothesis; "this IS exploitable (marker reflected, control inert)" is a
finding. Report the latter only. Attach evidence, redact secrets, then chain
into the next follow-up.

## Related doctrine (reach at the moment — everything links)

- **Blocked** by a WAF/filter → `bypass_lookup(defense)`.
- **Confirmed a finding** → `list_chains` + `chain_links` for the escalation.
- **Crafting a probe** → `payload_lookup(class)` + `read_payload`.
- **Sub-agent/model failed** → `model_fallback(signal)` + `retry_guidance(signal)`.
- **Am I done?** → `engagement_status()`.
- **Need the campaign plan** → `read_playbook(web-application)` / `api-security`.
- **Detailed methodology for one class** → `technique_lookup(ssrf|ssti|jwt|...)`
  (summary + objectives + how-to-test + tricks + verify).
- **Framework-specific tricks** → `framework_tricks(laravel|django|...)` after
  `detect_framework` (signals + known vulns/CVEs + attack tricks).
- **Need to run an external exploit tool** → `tool_lookup` → `ensure_tool` → `read_tool_manual`.
- **Need domain-specific resources beyond Blitz's own data** → `resource_lookup(web|recon|payload|privesc|...)` for the curated index.
- **Ground a finding in standard IDs for the report** → `taxonomy(web|api|cwe|asvs, ...)`.
- **Verification** → `verify-finding` skill. **Review** → `adversarial-review`.
- **The full map** → `doctrine_map` (phase → skill → tools → data).
