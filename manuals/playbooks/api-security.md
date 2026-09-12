# API Security Playbook

Use for authorized GraphQL, OpenAPI/REST, gRPC, WebSocket, or API-heavy web application testing.

## Inputs

- API base URLs, schemas/specs, sample requests, Postman collections, or captured traffic.
- Authentication method, test accounts, token refresh behavior, and tenant/role boundaries.
- Rate limits, unsafe methods, destructive endpoints, and fuzzing approval.

## Workflow

1. **Inventory and classification**
   - Identify API style: OpenAPI/REST, GraphQL, gRPC, WebSocket, SOAP, or mixed.
   - Collect schemas, endpoints, auth headers, roles, and representative requests.
   - For API-heavy web apps, run this playbook alongside `web-application.md`.

2. **Passive mapping**
   - Even when API documentation is available, capture at least one authenticated session and cross-check against the docs.
   - Use captured traffic, `mitmproxy` (see `../web/tools/mitmproxy.md`), `mitmproxy2swagger` (see `../web/tools/mitmproxy2swagger.md`), crawlers, and existing documentation.
   - Recover OpenAPI definitions only from representative authorized traffic.

   ```bash
   mitmdump -w /tmp/api.flows
   mitmproxy2swagger -i /tmp/api.flows -o /tmp/openapi.yaml -p https://api.example.com
   ```

3. **Protocol-specific discovery**
   - GraphQL: fingerprint with `graphw00f` (see `../web/tools/graphw00f.md`); attempt schema recovery with `clairvoyance` (see `../web/tools/clairvoyance.md`) only when approved.
   - REST/OpenAPI: use `kiterunner` (see `../web/tools/kiterunner.md`) for API route discovery and `schemathesis` (see `../web/tools/schemathesis.md`) for schema-driven tests.
   - gRPC: use `grpcurl` (see `../web/tools/grpcurl.md`) with reflection or supplied `.proto` files.
   - WebSocket: use `websocat` (see `../web/tools/websocat.md`) after capturing valid messages.

   - If signing blocks tool execution, defer to after the proxy is built. Record in `todo.txt`: `[DEFER] Phase 3 — resume after proxy`.

   (See `../web/README.md` for web and API tool selection.)
   ```bash
   # kiterunner — API route discovery
   kr scan <target-url> -w /path/to/routes.kite -A=apiroutes-240328

   # schemathesis — schema-driven testing
   st run https://target/openapi.json --checks all --url https://target

   # grpcurl — service enumeration via reflection
   grpcurl -plaintext <target>:50051 list
   grpcurl -plaintext <target>:50051 describe <service>

   # websocat — WebSocket testing
   websocat ws://<target>/ws
   ```

4. **API documentation-driven coverage** (if API specs, Swagger/OpenAPI docs, or developer documentation are available)
   - Parse documentation to extract a complete endpoint list with methods, parameters, and expected input types.
   - Use this list to measure test coverage — do not rely on wordlist-based discovery alone.
   - Ensure every documented endpoint with user-controllable input is tested for injection, authorization, and business logic flaws.
   - Cross-reference ffuf/kiterunner discoveries against the documentation to identify undocumented endpoints (shadow APIs).

5. **Client-side signing and request protection** (execute when direct API requests return signature errors, device verification failures, or opaque rejection codes)
   - **Bypass test** (always execute first): test whether signature validation can be bypassed — send malformed, empty, or constant values. If validation is weak, document the bypass as a finding and proceed without a signing proxy.
      - **Bypass confirmed:** automated tools are immediately usable. Execute the Automated Baseline Gate below, injecting the bypass values as static headers (e.g., `-H "X-Signature: "`). Then proceed to Phase 6.
      - **Bypass failed:** complete all steps below, then execute the Automated Baseline Gate through the proxy before proceeding to Phase 6. Record in `decisions.txt`: `[PROXY_BUILT] <approach> — verified: yes`.
        - Locate the frontend application (SPA JavaScript bundle, mobile app, or SDK) and extract: signing algorithm and inputs, required custom headers, public keys or shared secrets, and API constants. Even when API documentation is available, fetch and analyze the frontend JS — documentation describes the spec, JS reflects the actual implementation. Discrepancies are high-value findings. (See `../reverse-engineering/README.md` for binary/JS analysis tool selection.)

          ```bash
          curl -sk https://<frontend-host>/main.js -o /tmp/main.js
          grep -iE '(signature|sign|hmac|sha1|sha256|x-sign|x-timestamp)' /tmp/main.js
          grep -iE '(encrypt|decrypt|aes|rsa|pub.?key|iv|cipher)' /tmp/main.js
          grep -iE '(app.?id|client.?id|api.?key|secret|host|base.?url)' /tmp/main.js
          ```
        - Implement a signing script, then confirm a signed request succeeds before proceeding.
        - **Encrypted request/response handling**: if API responses are base64-encoded binary rather than plaintext JSON, identify the encryption scheme from frontend code or API documentation, build encrypt/decrypt functions, and confirm decrypted responses match expected JSON before proceeding. All subsequent phases must route through the encryption layer.
        - **Proxy cost-benefit assessment**: before building a full mitmproxy addon, enumerate all user-controllable parameters across documented endpoints. Full proxy required if ANY: free-text fields, file uploads, complex nested JSON bodies, or path parameters accepting arbitrary strings. `sqlmap --eval` / manual sufficient ONLY IF all parameters are enum-type, numeric IDs, or fixed-format strings. Record the decision in `decisions.txt`: `[PROXY_DECISION] injectable params: <count/types> — decision: <full proxy / sqlmap --eval / manual> — reason: <why>`.
        - Before choosing a proxy approach, check the Decision Tree in `../web/README.md` — it maps common signing schemes to specific tool recommendations.
        - **Proxy implementation options** (lightest to heaviest):
          - `sqlmap --eval` with inline signature computation — sufficient for simple signing schemes.
          - Local HTTP server that accepts plaintext, wraps in the custom protocol, forwards, and returns decrypted responses.
          - `mitmproxy` addon script for bidirectional encryption handling.
        - **Signing proxy quick-start** (adapt algorithm and headers to the target):

          ```python
          # /tmp/sign_addon.py
          import hashlib, time, uuid
          from mitmproxy import http

          TOKEN = open("/tmp/access_token.txt").read().strip()

          def request(flow: http.HTTPFlow):
              ts = str(int(time.time()))
              rid = str(uuid.uuid4())
              url = flow.request.pretty_url
              sig = hashlib.sha1((url + " " + ts + " " + rid).encode()).hexdigest()
              flow.request.headers["X-Timestamp"] = ts
              flow.request.headers["X-Request-Id"] = rid
              flow.request.headers["X-Signature"] = sig
              flow.request.headers["Cookie"] = "session_token=" + TOKEN
          ```

          ```bash
          mitmdump -s /tmp/sign_addon.py --listen-port 8080 --set ssl_insecure=true --set http2=false &
          # Verify: curl -sk -x http://127.0.0.1:8080 https://target/endpoint
          ```

          Force `--set http2=false` when the target validates mixed-case custom headers. Use `--technique=BEUS` with sqlmap to skip time-based injection (per-request timestamp changes destabilize baselines). Details: `../web/tools/mitmproxy.md`.

        - After building a proxy, verify one request returns non-401, then execute the Automated Baseline Gate. For proxy-incompatible tools (nikto), inject auth headers directly via the tool's own header flags.

   - **Automated Baseline Gate** (mandatory — execute before proceeding to Phase 6, regardless of bypass or proxy path):

     | Tool | Purpose | Routing |
     |------|---------|---------|
     | `nuclei` | Known CVE and misconfig scan | Proxy or direct with static auth headers |
     | `ffuf` | API path discovery (SecLists `api/endpoints.txt` + `common.txt`) | Proxy |
     | `sqlmap` | Injection test on all parameterized endpoints | Proxy; use `--technique=BEUS` to skip time-based |
     | `dalfox` or `xsstrike` | XSS on reflected parameters | Proxy |

     - If bypass confirmed: inject static bypass headers directly (e.g., `-H "X-Signature: <bypass_value>"`).
     - If proxy built: route all tools through the proxy (`--proxy=http://127.0.0.1:8080`).
     - For proxy-incompatible tools (nikto): inject auth headers via the tool's own flags (`-Add-header`).

     Record in `decisions.txt`: `[BASELINE_COMPLETE] tools: nuclei/ffuf/sqlmap/dalfox — date: <date>`

6. **Auth and authorization checks**
   - Test missing auth, token reuse, role/tenant boundaries, object-level authorization, and method restrictions.
   - Preserve request/response evidence for every role tested.
   - Specific checks and tools:
     - **JWT**: test `alg:none`, weak HS256 secret, `kid` header injection — use `jwt_tool` (see `../web/tools/jwt_tool.md`) `<token> -M pb` for a playbook scan, then `jwt_tool <token> -M at` for all tests. If the token format is not JWT (opaque, UUID-based, session ID), record in `decisions.txt`: `[N/A] jwt_tool — reason: token format is <format>, not JWT`.
     - **BOLA / IDOR**: replace object IDs (user IDs, resource IDs) with IDs from another test account; confirm isolation.
     - **Broken function-level auth**: call admin-only endpoints (e.g., `DELETE /users/<id>`, `/admin/*`) with low-privilege tokens.
     - **Mass assignment**: send extra fields in POST/PUT body that should be read-only (e.g., `role`, `is_admin`).
     - **Token leakage**: check error responses, debug headers, and logs for credential material.
     - Route all cross-role tests through `mitmproxy` or ZAP to capture full request/response pairs as evidence.

   **Endpoint × role authorization matrix (mandatory):** Build an explicit matrix of every endpoint against every test role. Test each cell — do not assume that if one admin endpoint blocks a low-privilege user, all admin endpoints do. Record the result (allowed / denied / error) for each cell. Untested cells are coverage gaps, not passes.

   **Credential discovery handling:** When credentials are found during API testing (JWT secrets, API keys in error responses, tokens in debug headers, hardcoded credentials in schema examples), immediately test them against all discovered API endpoints and authentication services before continuing to the next test phase.

   **Multi-platform auth delivery:** The same API may accept different authentication delivery methods per client platform — Cookie for web, Authorization header for mobile, API Key header for third-party integrations, query parameter for callbacks. When any auth method returns 401 or an auth error, systematically test all alternative delivery methods before concluding the endpoint requires that specific method. Check API documentation, frontend code, and SDK examples for platform-specific auth instructions.

   ```bash
   # JWT audit — playbook scan first, then all tests
   jwt_tool <token> -M pb
   jwt_tool <token> -M at
   # Replay request as different role
   mitmdump -s /tmp/swap_auth.py -r /tmp/api.flows
   ```

7. **Test data preparation** (if test accounts lack the business objects needed to exercise API endpoints)
   - Review the API inventory from Phase 1 and identify endpoints that require specific resources to exist (e.g., create an organization, join a group, post content, upload files, create relationships between accounts).
   - Use API documentation or discovered creation endpoints to build the minimum set of business objects needed to expand the testable surface.
   - Create resources using each test role to establish cross-role test scenarios (e.g., Role A owns a resource, Role B attempts to access it for BOLA testing in Phase 8).
   - Record all created resources (IDs, types, endpoints used) for post-test cleanup and to support IDOR testing in Phase 8.

8. **Active testing**

   **Pre-check (BLOCKING):**
   1. Confirm the Automated Baseline Gate is complete — `decisions.txt` contains `[BASELINE_COMPLETE]`. If not: return and execute it now.
   2. If a signing proxy or signing script was built in Phase 5, verify with one test request that the proxy returns non-401 before proceeding.
   3. All automated tools in this phase must route through the proxy (or use direct header injection for proxy-incompatible tools).

   Active testing is the core vulnerability assessment phase. Break it into focused sub-phases.

   8.1. **Input validation and injection**
   - Test API parameters for SQL injection, NoSQL injection, command injection, LDAP injection, and XML external entity (XXE) attacks.
   - Use `sqlmap` (see `../web/tools/sqlmap.md`) with API-specific options: save a representative request to a file and run `sqlmap -r request.txt --batch`; for JSON bodies use `--data` with the correct `--headers="Content-Type: application/json"`.
   - Test for SSRF through URL and file parameters — supply internal addresses (`http://169.254.169.254/`, `http://127.0.0.1:<port>`) and observe responses.
   - Fuzz all input vectors (path, query, header, body) with type-boundary and encoding-bypass payloads.

   **Per-parameter injection coverage:** Do not test only one representative request per endpoint. For each endpoint, identify all injectable parameters (path, query, header, body fields) and test each against applicable injection types. When sqlmap reports clean on default settings, escalate to `--level=5 --risk=3` before accepting a negative result.

   ```bash
   # API SQL injection with saved request
   sqlmap -r /tmp/api_request.txt --batch --level=3 --risk=2
   # JSON body injection
   sqlmap -u "https://api.example.com/v1/search" --data='{"query":"test"}' --headers="Content-Type: application/json" --batch
   ```

   8.2. **Business logic and rate limiting**
   - Test rate limits on sensitive endpoints: login, password reset, OTP verification, account creation.
   - Test pagination abuse: negative offsets, zero or excessively large page sizes, non-numeric page parameters.
   - Test race conditions on state-changing operations (balance transfers, coupon redemption) by sending concurrent requests.
   - Test for IDOR across all identified object references — enumerate IDs, UUIDs, and sequential identifiers.

   8.3. **GraphQL-specific attacks** (if GraphQL detected in Phase 1 or Phase 3)
   - Batch query abuse: send arrays of queries in a single request to bypass rate limiting.
   - Alias-based DoS: duplicate the same expensive field under many aliases.
   - Nested query depth attacks: submit deeply nested queries (`{a{b{c{d{...}}}}}`) to test depth limiting.
   - Field suggestion abuse: use typos to extract valid field names from error messages.
   - Directive injection: test for unexpected behavior with custom or repeated directives.
   - Reference `clairvoyance` for schema recovery when introspection is disabled.

   8.4. **Error handling and information disclosure**
   - Trigger errors with malformed inputs: invalid types, oversized payloads, null bytes, unexpected encodings.
   - Check responses for stack traces, debug endpoints, internal path disclosure, and verbose error messages.
   - Probe for API version information leakage in headers, error bodies, and `/debug` or `/status` endpoints.
   - Test for different error behavior between authenticated and unauthenticated requests.

   Validate all findings manually before reporting — API scanners often surface schema mismatches rather than exploitable issues.

   8.5. **CORS misconfiguration testing**
   - Test for overly permissive CORS policies that allow arbitrary origins to read API responses.
   - Send requests with crafted `Origin` headers and check `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` in responses.
   - Test for null origin acceptance and wildcard with credentials.
   - If preflight (OPTIONS) and actual request CORS behavior differ, record the discrepancy and test further: try the actual request with the same Origin, test with different HTTP methods, and check whether `Access-Control-Max-Age` caching could cause browsers to use cached preflight permissions.

   ```bash
   # Test CORS with arbitrary origin
   curl -s -H "Origin: https://evil.com" -I https://api.example.com/v1/endpoint | grep -i "access-control"
   # Test null origin
   curl -s -H "Origin: null" -I https://api.example.com/v1/endpoint | grep -i "access-control"
   # Test with credentials flag
   curl -s -H "Origin: https://evil.com" -H "Cookie: session=TOKEN" -I https://api.example.com/v1/endpoint | grep -i "access-control"
   ```

9. **API versioning and deprecated endpoints**
   - Test for older API versions (`/v1/`, `/v2/`) that may lack security controls present in the current version.
   - Check for shadow or zombie API endpoints not listed in documentation — use `kiterunner` with historical wordlists.
   - Compare auth enforcement, input validation, and rate limiting between API versions.
   - Document any deprecated endpoints that remain reachable and lack current protections.

## Cross-References

- `internal-network.md` — when the API is on an internal network requiring broader assessment.
- `external-attack-surface.md` — for discovering additional API endpoints through subdomain and port enumeration.
- `password-audit.md` — for cracking JWT secrets, API keys, or captured credentials.
- `source-code-audit.md` — when API source code is available for static analysis of endpoints and auth logic.
- `web-application.md` — WebSocket and general web testing.
- `post-exploitation.md` — when a confirmed API vulnerability leads to shell access; see also `../exploitation/README.md` for exploitation path selection.
- `../reverse-engineering/README.md` — when frontend JS analysis is needed to extract signing or encryption logic.
- `reporting-workflow.md` — report structure and delivery.

## Expected Artifacts

- API inventory by protocol and base URL.
- Schemas/specs, recovered specs, and representative request samples.
- Auth matrix by role and endpoint.
- Fuzzing and route-discovery results with rate limits noted.
- Test data inventory: created resources, IDs, creation endpoints, and cleanup plan.

## Stop When

Before proceeding to reporting, verify each checklist item. If any item fails, return to the relevant phase.

1. **Endpoint discovery:** If API documentation is available, at least 80% of documented endpoints with user-controllable input have been probed. List skipped endpoints with justification.

2. **Test depth per endpoint:** For every accessible endpoint (non-404), confirm these dimensions were covered where applicable. An endpoint only counts as "tested" when all applicable dimensions are done:
   - Tested with each authentication method the API supports — not just the first one that worked.
   - Resource-ID endpoints tested with IDs belonging to other users/resources (IDOR), not only the tester's own.
   - Each user-controllable field tested for injection — not one representative field per endpoint.
   - Parameters tested with boundary values (zero, negative, empty, oversized, null, type mismatch).

3. **Authorization matrix:** The endpoint × role matrix is complete with no untested cells. Each cell records: allowed / denied / error.

4. **Cross-cutting tests completed:** Authentication method interactions, rate limiting on sensitive operations, and older API versions compared for missing controls.

5. **Tool utilization:** All automated tools adapted via proxy/wrapper have been re-run through the adaptation layer. If the API requires custom signing, confirm nuclei and ffuf were executed through a signing proxy, and nikto was run with auth headers injected directly (`-Add-header`) — unauthenticated runs against a signed API do not count as coverage. This corresponds to the Automated Baseline Gate between Phase 5 and Phase 6 — if that gate was not executed, this item fails.

If a checklist item cannot be satisfied due to scope constraints (destructive operations, missing test accounts, undeployed features), document the gap explicitly rather than silently passing.
