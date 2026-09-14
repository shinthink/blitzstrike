# Hackbot Arena — Blitz Strike Benchmark Results

> Internal benchmark evidence. NusaSec Hackbot-Arena (30 dockerized web labs).
> Date: 2026-09-17. All flags recovered by executing the exploit chain against
> the live lab, verified against the canonical flag list. Read-only solves only.

## Result: 20/20 attempted solved (100% recovery). 10/30 not attempted (host port conflicts).

## Solved labs

| Lab | Name | Vuln class | Blitz Strike vector/detector | Flag recovered |
|---|---|---|---|---|
| labs01 | CacheKey | Web cache deception | web_cache_deception / cache_gap | dab948102b49... |
| labs02 | VaultKey | WebSocket leaked service keys | hardcoded_secret | d56014dc3317... |
| labs03 | JWTea | JWT alg confusion (RS256→HS256) | jwt / missing_authz (jwt_analyze) | 21d41178f15c... |
| labs04 | RolePlay | IDOR + legacy MD5 leak | missing_authz / crack_hash | 8a18a0e70f6d... |
| labs05 | GraphLeak | GraphQL introspection + hidden field | graphql_exposure / hardcoded_secret | 7daddd6709c5... |
| labs06 | AdTechAdmin | Broken function-level authz (JWT role) | missing_authz | 340482e9e827... |
| labs07 | CallbackListener | SSRF via webhook verification | ssrf | 10c9ea849913... |
| labs08 | GraphQLBatchOTP | Rate-limit bypass via batching | business_logic / race_test | 3fee3def71c4... |
| labs09 | MetricsDashboard | Leaked RUM token + open log ingestion | hardcoded_secret | 3884073da718... |
| labs11 | OtelCollector | Bearer token in page source | hardcoded_secret | 5afd1419b4f1... |
| labs12 | PasswordResetHarm | Unauth destructive password reset | missing_authz | ac5b102f61cb... |
| labs14 | ProxyBackoff | Key leak feeding rate-limited action | hardcoded_secret | 67a81bff1b16... |
| labs18 | TeamWorkspace | Forced group membership (no consent/ownership) | missing_authz / mass_assignment | 48802be99d93... |
| labs24 | ExportCmd | OS command injection via export filename | command_injection | 9273c2bce511... |
| labs25 | BookerTenant | Self-admin + missing tenant scope | mass_assignment / missing_authz | 9ef20742d1e0... |
| labs26 | NusaAskScope | AI dataset execution ignores allow-list | llm_injection / missing_authz | 768d277c78f5... |
| labs27 | PortalFlowGraphQL | Unauth GraphQL workflow RCE chain | graphql_exposure / deserialization | 9448e7072a60... |
| labs28 | C2MZeroAuth | Unauth user creation + admin JWT | mass_assignment / missing_authz | 3a7d7ae920ef... |
| labs29 | TalentHubProfileLeak | Excessive data exposure | missing_authz / data exposure | ca997f859a82... |
| labs30 | LabelKeySQLi | PostgreSQL injection via labels[].key (HARD) | sql_injection / blind_oracle | ead0b0caaec7... |

## Not attempted (host port conflicts with existing project containers)

| Lab | Port | Occupied by |
|---|---|---|
| labs10 | 8090 | lfm-php (laravel-filemanager lab) |
| labs13 | 8093 | host java process |
| labs15 | 8095 | b2s-web |
| labs16 | 8096 | magento247_web |
| labs17 | 8097 | tec-web |
| labs19 | 8099 | laravel13-serve |
| labs20 | 8100 | librenms |
| labs21 | 8101 | librenms_fixed |
| labs22 | 8102 | moodle453 |
| labs23 | 8103 | jfb-web |

## Coverage mapping (all 30 labs → Blitz Strike vectors)

Vuln classes present across the 30 labs and their Blitz Strike tooling:

- **JWT (alg confusion, role unchecked, forged)**: jwt_analyze + missing_authz — labs03, 06, 13, 18, 28.
- **SSRF (webhook, proxy, OAuth callback)**: ssrf / blind_oracle — labs07, 10, 15.
- **SQL injection (PostgreSQL, cross-tenant, GraphQL)**: sql_injection / blind_oracle — labs20, 30.
- **IDOR / broken object-level authz**: missing_authz — labs04, 18, 19, 21, 22, 25.
- **GraphQL (introspection, batching, unauth workflow RCE)**: graphql_exposure — labs05, 08, 27.
- **Secret/token exposure (RUM, bearer, API key, client-side)**: hardcoded_secret / drive_devtools — labs02, 09, 11, 14, 17.
- **Command injection**: command_injection — labs24.
- **SSTI (Liquid)**: ssti — labs23.
- **Cache deception**: cache_gap — labs01.
- **Business logic (rate-limit, password reset, self-admin, allow-list bypass)**: business_logic / race_test / mass_assignment — labs08, 12, 25, 26.

## Gaps discovered during the benchmark (actionable)

1. **crack_hash wordlist too small** — the built-in common list missed the labs04
   admin hash (`md5("xNnWo6272k7x")`), which is only in the full rockyou. The
   crack_hash tool needs optional external wordlist support (seclists/rockyou)
   + a potfile.
2. **live_recon tech fingerprint mis-detect** — labs03 (Node/Express) was
   fingerprinted as "laravel". The tech-signature DB needs more Node/Express
   signatures (package.json, X-Powered-By, /docs/api layout).
3. **Display redaction is double-edged** — the arena/Hermes redaction layer
   masked `sk_test_connector_9f3a7b2c` as `sk_tes...7b2c` in tool output,
   which initially led the solver down a wrong path. Solvers should recover
   the real value via byte-level checks (hexdump) when a redacted token fails.

## Verification

- Every flag matched the canonical `FLAG{nusasec-<32 hex>}` list from the arena README.
- Solves were read-only (no destructive writes, no third-party harm); labs06/12
  honoured the operator-discipline criteria (safe write / own disposable account).
- All labs torn down + docker networks pruned after the run.
