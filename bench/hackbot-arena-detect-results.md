# Hackbot Arena — Blitz Strike DETECTION Benchmark (TP/FP/FN)

> Runs the real Blitz Strike detectors (taint engine + 24 complex-bug detectors +
> sink scanner) against all 30 labs' SOURCE, then classifies each signal against
> the lab's canonical vuln class. Detection accuracy ≠ exploit capability —
> this measures what the DETECTORS fire, honestly.

## Headline numbers

| Metric | Count | Notes |
|---|---|---|
| Labs scanned | 30 | source-level, all labs |
| VERIFIED findings (TP) | 7 | detector fired on the actual vuln class |
| FALSE POSITIVES | ~25 signals | missing_authz (18) + hardcoded_secret (6) + generic sinks |
| FALSE NEGATIVES | ~17 labs | actual vuln not detected by any detector |

## Verified findings (TP — signal matches the lab's real vuln)

| Lab | Detector fired | Actual vuln | Signal |
|---|---|---|---|
| labs07 CallbackListener | taint `http_request` | SSRF via webhook | correct |
| labs10 OAuthCallback | taint `http_request` | SSRF via auth_url | correct |
| labs15 SsrfProxy | taint `http_request` | Unfiltered SSRF | correct |
| labs14 ProxyBackoff | `hardcoded_secret` | Key leak feeding /test | correct |
| labs17 StorefrontUpload | `hardcoded_secret` | API key in client source | correct |
| labs19 SpendGate | taint `code_execution` | RQL injection | correct (eval sink) |
| labs06 AdTechAdmin | `hardcoded_secret` | Hardcoded JWT secret (forge enabler) | valid secondary |

## False positives (FP)

**#1 — `missing_authz` fires on ~18 labs (dominant FP).** `detectRouteAuthz`
flags any route whose surrounding window lacks a RECOGNIZED auth pattern. The
labs' routes are (a) public-by-design (register/login/health) or (b) guarded by
a decorator the detector doesn't recognize (`@require_auth`, `@login_required`,
`@limiter`, `before_request`, JWT middleware). Result: 18 labs flagged "missing
authz" where the real bug is something else (cache deception, SSTI, rate-limit,
etc.).

**#2 — `hardcoded_secret` on flag/benign literals.** Fired on labs01/02/03/25/30
where the "secret" is the FLAG value itself (seeded `api_key=FLAG`) or a non-secret
literal — not an actual leaked credential. (labs09/11, the real RUM/bearer token
leaks, were NOT caught — the tokens sit in JS/HTML that the detector misses.)

**#3 — Generic PHP-ish sink scanner.** `Local file inclusion`, `RCE (command
execution)`, `Open redirect / header injection` fired on Node/Python apps where
`require`/`fetch`/`redirect` matched PHP-oriented sink tokens — not real vulns.

## False negatives (FN — the actual vuln was not detected)

labs01 (cache deception), labs02 (WS key leak), labs03 (JWT alg confusion),
labs04 (IDOR+MD5), labs05 (GraphQL introspection), labs08 (rate-limit bypass),
labs09 (RUM token), labs11 (bearer token), labs20 (SQLi cross-tenant),
labs22 (business logic), labs23 (Liquid SSTI), labs24 (command injection),
labs26 (AI allow-list bypass), labs27 (GraphQL workflow RCE),
labs28 (mass assignment + admin JWT), labs29 (data exposure), labs30 (SQLi via JSONB key).

## Root causes

1. **Detectors are PHP/WordPress-tuned; the arena is Node/Python.** The scanner
   `SINKS` (shell_exec, $wpdb->query, DB::select) and `detectSqlInjection`
   ($wpdb/mysqli/pg_query/whereRaw) target PHP idioms. Node `sqlx`/string-concat
   SQL, Python `subprocess.run(shell=True)`, and `urllib` SSRF are outside those
   patterns → the specific classes go undetected (FN).
2. **`detectRouteAuthz` has no decorator/middleware auth model** → broad
   `missing_authz` FP.
3. **No detector for several classes present in the arena:** JWT algorithm
   confusion (static), web cache deception, rate-limit bypass via batching,
   Python command injection, Liquid/Jinja SSTI, Node SQLi, mass-assignment.

## Actionable fixes (priority order)

1. `detectRouteAuthz`: recognize decorator/middleware auth (`@require_auth`,
   `@login_required`, `@jwt_required`, `@limiter`, `before_request`, `@app.before_request`)
   and skip public-by-design routes (register/login/health/static).
2. Extend scanner `SINKS` + `detectSqlInjection` with Node/Python idioms:
   `subprocess.run(..., shell=True)`, `child_process.exec`, `os.system`,
   `sqlx::query(&format!(...))`, `urllib.request.urlopen`, `requests.get`.
3. Add class detectors: `jwt_alg_confusion` (RS256 + HS256 dual verify path),
   `command_injection_python`, `ssti` (Liquid/Jinja `{{ }}` + render_template_string),
   `cache_deception` (greedy route regex + static-ext cache).
4. `detectHardcodedSecret`: suppress `FLAG{...}` literals + known non-secret markers.
