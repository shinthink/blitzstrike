# Web Application Playbook

Use for authorized web applications, APIs, CMS targets, or HTTP services discovered during reconnaissance.

## Inputs

- Base URLs, allowed hosts, authentication details if any.
- Test depth, rate limits, prohibited paths, and whether active exploitation is allowed.
- API definitions such as OpenAPI, GraphQL schema, Postman collections, or sample requests.

## Workflow

1. **Baseline inventory**
   - Probe URLs with `httpx` (see `../information-gathering/tools/httpx.md`), `whatweb` (see `../information-gathering/tools/whatweb.md`), and `wafw00f` (see `../information-gathering/tools/wafw00f.md`).
   - Record redirects, cookies, headers, TLS details, WAF indicators, and technologies.

   (See `../information-gathering/README.md` for reconnaissance tool selection.)
   - **TLS cipher audit**: run `sslscan` (see `../vulnerability/tools/sslscan.md`) or `testssl.sh` (see `../vulnerability/tools/testssl.sh.md`) to enumerate all accepted cipher suites and check for known TLS attacks (ROBOT, DROWN, CCS injection, Ticketbleed, Heartbleed) — do not rely on manual `openssl s_client` version checks alone. Flag 3DES, RC4, non-PFS suites, and missing TLS 1.3 support.
   - **Wildcard certificate → subdomain enumeration**: if the TLS certificate contains a wildcard SAN (e.g., `*.example.com`), enumerate subdomains with DNS queries and probe each for distinct services or response codes.
   - **CORS origin reconnaissance**: if the `Access-Control-Allow-Origin` header names a specific origin (e.g., `https://app.example.com`), probe that origin for headers, CSP directives, cookies, and technology details — its response metadata often reveals API endpoints, internal architecture, or unauthenticated paths. Run `nikto` and `nuclei` against any origin that returns HTTP 200 with real content.
   - **Certificate transparency**: query `crt.sh` for historical certificates to discover subdomains not found by DNS enumeration. Probe each discovered subdomain — different HTTP status codes (200, 403, 400 vs. default 404) indicate distinct routed services that require independent testing.

   ```bash
   httpx-toolkit -l urls.txt -title -tech-detect -status-code -json -o httpx_inventory.json
   whatweb -a 3 <target-url> --log-json=/tmp/whatweb.json
   wafw00f <target-url> -o /tmp/waf_result.txt
   ```

2. **Crawling and endpoint discovery**
   - Crawl with `katana` (see `../web/tools/katana.md`), `gospider` (see `../web/tools/gospider.md`), `hakrawler` (see `../information-gathering/tools/hakrawler.md`), ZAP, or mitmproxy captures.
   - Use `ffuf`, `gobuster`, `feroxbuster`, and `dirsearch` with appropriate wordlists.
   - Use `arjun` for parameter discovery (see `../web/tools/arjun.md`).
   - If GraphQL, OpenAPI, gRPC, WebSocket, or API-heavy behavior is discovered, switch to `api-security.md` for API-specific testing.

   (See `../web/README.md` for web tool selection.)
   - **Frontend JS static analysis**: download all JavaScript files loaded by the target (check `<script src=...>` tags in the HTML source) and search for hardcoded API endpoints, internal URLs, subdomains, tokens, and secrets to discover internal services and attack surfaces not reachable by brute-forcing or crawling.

     ```bash
     # Download JS files
     curl -sk https://<target>/main.js -o /tmp/main.js
     # Search for URLs, API paths, subdomains, and secrets
     grep -oE 'https?://[a-zA-Z0-9._:/-]+' /tmp/main.js | sort -u
     grep -iE '(api[_-]?key|secret|token|password|authorization)' /tmp/main.js
     ```

   - **Target IP port scan**: when testing a web application, do not limit scanning to ports 80/443. Run a full TCP port scan against the target IP to discover additional services — HTTP on non-standard ports, admin panels, debug interfaces, or database services may be exposed.

   Run `ffuf` or `feroxbuster` for directory enumeration with appropriate wordlists (see `../web/tools/ffuf.md` and `../web/tools/feroxbuster.md`).

   ```bash
   katana -u <target-url> -d 3 -jc -kf all -silent -o katana_urls.txt
   ffuf -u <target-url>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -mc 200,301,302,403 -o ffuf_dirs.json -of json
   arjun -u <target-url> -oJ arjun_params.json
   ```

   **Endpoint inventory completeness:** Before proceeding to testing, compile a deduplicated list of all discovered endpoints and parameters. If crawling and brute-forcing yield fewer than 10 unique endpoints for a non-trivial application, retry with additional wordlists, deeper crawl depth, technology-specific paths, and different file extensions. This inventory drives all subsequent testing.

   **Management interface discovery:** When directory enumeration discovers database management interfaces (phpMyAdmin, Adminer, pgAdmin), service dashboards (Kibana, Grafana, Redis Commander), or application admin panels, immediately test them with all credentials from the working credential list. These interfaces often accept database or application credentials that are restricted at the network level but unrestricted through the web UI.

   **Unauthenticated endpoint discovery:** Do not assume that a globally authenticated API has zero unauthenticated endpoints. CSP `report-uri` directives, CORS-referenced origins, error handlers, health checks, and callback URLs often bypass auth. When any endpoint returns a non-401 response (including 200, 400, 403), treat it as a separate attack surface and apply the full test matrix (injection, SSRF, rate limiting, method fuzzing) regardless of whether its response body appears "empty" or "static."

3. **Automated DAST**
   - Run `nuclei` and `nikto` early for known CVEs and common misconfigurations.
   - Use ZAP baseline/API scans for passive and API-oriented checks.
   - Use ZAP full scans only with explicit authorization.

   (See `../vulnerability/README.md` for vulnerability scanning tool selection.)

   Run `nikto` with JSON output (see `../web/tools/nikto.md` for variants including HTML/CSV reports).
   Run `nuclei` from the vulnerability category for template-based checks (see `../vulnerability/tools/nuclei.md`).

   ```bash
   nikto -h <target-url> -Format json -o /tmp/nikto.json
   # Locate nuclei templates first (path varies by Kali version)
   TMPL=$(find ~ -name "nuclei-templates" -type d 2>/dev/null | head -1)
   nuclei -u <target-url> -t "$TMPL/http/misconfiguration/" \
     -t "$TMPL/http/exposures/" -t "$TMPL/http/technologies/" \
     -severity critical,high,medium -o /tmp/nuclei_web.jsonl -jsonl
   ```

   **Zero-findings fallback:** If both scanners report zero findings, do not accept the result at face value. Re-run with expanded scope (e.g., nuclei with additional `-t` paths for `http/cves/` and `http/vulnerabilities/`, nikto with `-Tuning 123`), and document the recheck. For nuclei specifically, add `-v` to confirm templates are being loaded and requests are being sent — silent zero output often means the template path was not resolved or the target was not reachable. Verify the scanners reached the application by checking for non-empty response data in the verbose output.

4. **Targeted vulnerability testing**
   - Test SQL injection with `sqlmap` after identifying candidate parameters.
   - Test XSS, SSTI, SSRF, path traversal, file upload, command injection, JWT, CORS, and auth logic according to observed features.
   - Use `sstimap` (see `../web/tools/sstimap.md`) for SSTI candidates and CMS-specific tools such as `wpscan` (see `../web/tools/wpscan.md`) or `joomscan` (see `../web/tools/joomscan.md`) when fingerprints match. Run `cmseek` first to identify the CMS before choosing a CMS-specific scanner (see `../web/tools/cmseek.md`).

   (See `../web/README.md` for injection and vulnerability testing tool selection. When a confirmed vulnerability warrants shell access, see `../exploitation/README.md` for exploitation path selection.)

     ```bash
     cmseek -u <target-url>
     ```

   - **Command injection**: Use `commix` for systematic OS command injection testing (see `../web/tools/commix.md`).

     ```bash
     commix --url "http://target/page?param=INJECT_HERE" --level=3 --batch
     ```

   - **File upload testing**: test file type restrictions, path traversal in upload filename, polyglot files (e.g., GIF header + PHP), and upload size limits.
   - **Deserialization**: identify serialized objects in parameters or cookies; test with known gadget chains (Java/PHP/.NET). For PHP deserialization, use `phpggc` to generate gadget chains (see `../web/tools/phpggc.md`). For padding oracle attacks on CBC-mode encrypted cookies/tokens, use `padbuster` (see `../web/tools/padbuster.md`).
   - **HTTP request smuggling**: test CL/TE and TE/CL confusion where front-end and back-end servers differ.
   - **SSRF**: test URL and file parameters for internal network access, cloud metadata (`http://169.254.169.254`), and internal service enumeration.
   - **XXE**: test XML inputs for external entity injection; attempt out-of-band retrieval if inline response is not reflected.
   - **Security header analysis**:
     - Check for missing headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
     - Check CORS configuration: send varied `Origin` headers to detect wildcard or overly permissive policies.
     - Test CRLF injection with `crlfuzz`.
   - **Cross-service configuration comparison**: when multiple services share the same infrastructure (e.g., API server, frontend, enterprise API on the same IP or wildcard cert), compare their TLS cipher suites, security headers, CORS policies, and authentication requirements. Inconsistencies often reveal the weakest link — a frontend missing TLS 1.3 while the API supports it, or an internal API lacking auth while the public API enforces it.
   - **CSP source validation**: if the target sets a `Content-Security-Policy` with external script sources, verify each allowed domain resolves and is not susceptible to subdomain takeover. NXDOMAIN results for CSP-allowed domains are a CSP bypass risk.

   Run `sqlmap` with `--batch --dbs` on identified parameters (see `../web/tools/sqlmap.md` for full flags including tamper scripts, level/risk, and OS shell).

   Run `dalfox` for XSS detection (see `../web/tools/dalfox.md`).

   If template engine detected, test SSTI with `sstimap` (see `../web/tools/sstimap.md`).

   If WordPress is confirmed, run `wpscan` with user/plugin/theme enumeration (see `../web/tools/wpscan.md` for API token and brute-force options).

   **Per-endpoint coverage:** Every endpoint in the inventory from Step 2 must be tested against all applicable vulnerability classes (injection, XSS, SSRF, access control, file upload, deserialization) — not just endpoints that "look injectable." When sqlmap or other tools report zero findings on default settings, escalate sensitivity (e.g., `--level=5 --risk=3`) before accepting a negative result. Record tested and untested endpoints explicitly.

5. **Authenticated testing**
   - Preserve session handling and rate limits.
   - Route tools through ZAP or mitmproxy when request replay, evidence capture, or token handling is needed.

   (See `../web/README.md` for web testing tool selection.)
   - Test these auth and authorization checks manually after obtaining a session:
     - **Broken authentication**: session fixation, weak token entropy, missing re-auth on sensitive actions.
     - **JWT flaws**: `alg:none`, weak secret, `kid` injection — use `jwt_tool` to verify (see `../web/tools/jwt_tool.md`).
     - **IDOR / BOLA**: replace object IDs across roles and verify response differences.
     - **CORS misconfiguration**: send `Origin: https://evil.com` and check reflected header.
     - **CSRF**: confirm token binding; test with or without the `SameSite` cookie attribute.
     - **Privilege escalation**: access admin/privileged endpoints with a low-privilege account.
     - **Forced browsing**: access authenticated paths without cookies or with expired tokens.

   ```bash
   # Route sqlmap through authenticated proxy session
   sqlmap -u "<url>" --proxy http://127.0.0.1:8080 --cookie="session=<token>"
   # JWT analysis — run playbook scan first, then all tests
   jwt_tool <token> -M pb
   jwt_tool <token> -M at
   ```
   Capture traffic with `mitmdump` (see `../web/tools/mitmproxy.md` for listen flags and export formats).

   **Credential discovery handling:** When credentials are found during web testing (config files, backup archives, error messages, source code, default credentials), immediately test them against all discovered authentication endpoints — admin panels, APIs, databases, and SSH — before continuing to the next test phase.

6. **WebSocket testing**
   - If WebSocket endpoints are discovered during crawling or traffic capture:

   (See `../web/README.md` for web testing tool selection.)
     - Test handshake authentication: can you connect without valid credentials?
     - Test per-message authorization: send messages targeting other users' resources.
     - Test for injection in WebSocket messages (SQL, command, XSS payloads).
     - Monitor for sensitive data leakage in WebSocket frames.
   - See `../web/tools/websocat.md` for CLI-based WebSocket interaction.

7. **Business logic testing**
   - **Race conditions**: send concurrent requests to critical operations (account creation, balance transfers, voting) and check for duplicate processing.
   - **Workflow bypass**: skip steps in multi-step processes (e.g., jump from step 1 to step 3 in checkout) and verify server-side enforcement.
   - **Price/quantity manipulation**: modify price, quantity, or discount values in e-commerce requests and confirm server-side validation.
   - **Coupon/discount abuse**: test coupon reuse, stacking, negative values, and application to excluded items.

8. **Secrets and source artifacts**
   - Use `gitleaks` only when source code, repositories, archives, or artifacts are explicitly in scope.
   - If source code is available, hand off to `source-code-audit.md` for static analysis.

   ```bash
   gitleaks dir --redact -f json -r /tmp/gitleaks_report.json <repo-dir>
   ```

## Cross-References

- `external-attack-surface.md` — when additional subdomains or related infrastructure is discovered during web testing.
- `internal-network.md` — when the web application is on an internal network requiring broader network assessment.
- `password-audit.md` — for cracking captured password hashes or testing credential strength.
- `source-code-audit.md` — when application source code is available for static analysis.
- `reporting-workflow.md` — for structuring findings into a deliverable report.
- `api-security.md` — when GraphQL, REST API, gRPC, or WebSocket testing is needed.

## Expected Artifacts

- URL and endpoint inventory.
- Parameter list and interesting request samples.
- Screenshots and HTTP evidence.
- Scanner reports in machine-readable and human-readable formats.
- Confirmed findings with reproduction requests.

## Stop When

1. **Endpoint coverage:** All endpoints in the inventory have been tested against all applicable vulnerability classes, with results (positive or negative) recorded for each. "Tested" means each input field was exercised — not just one request per endpoint.
2. **Cross-resource authorization:** For endpoints with user-owned resources, tested with IDs/paths belonging to other users. Accessing only your own resources does not confirm isolation.
3. **Scanner validation:** DAST scanner zero-findings results have been rechecked with expanded scope or manual verification.
4. **Input depth:** Different input contexts (reflected in HTML, stored in DB, used in redirects, rendered in emails) tested separately — a finding in one context does not guarantee others are safe.
5. **Scope boundary:** High-risk active exploitation requires additional approval, or authentication/rate limits/WAF controls prevent further safe automation.
