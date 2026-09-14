# Changelog

All notable changes to Blitz Strike are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.4.33] — 2026-09-14

### Added — Security-State Lattice (beyond binary taint)

- New `src/security-state.ts`: models each value's SECURITY STATE
  (clean < whitelisted < validated < sanitized(context) < tainted) instead of
  binary tainted/not. A sink declares the minimum context it accepts.
- `detectWrongSanitizer` (wired into `complex_scan`/`blitz_file`) finds the
  complex bug class binary taint misses: a value sanitized for context X
  reaching a sink that needs Y (e.g. `sanitize_text_field()` into a SQL query),
  and pseudo-sanitizers (`base64_encode()`/`trim()` misused as escaping).
- New `security_state` tool: deterministic verdict for a sanitizer flow.
- Data-driven tables (sanitizers, pseudo-sanitizers, sink requirements) —
  the lattice is data, not guesses.

## [2.4.32] — 2026-09-14

### Removed

- Dropped a vendor-specific detection template and genericized planning
  wording in the changelog so no third-party product name appears in public
  artifacts (repo, changelog, or npm tarball).

## [2.4.31] — 2026-09-14

### Fixed — full CWE coverage in the compliance table (self-audit)

- Added 6 CWEs that detectors/writeups can emit but were missing from the
  compliance mapping: CWE-90 (LDAP), CWE-93 (CRLF/response-splitting), CWE-98
  (PHP RFI), CWE-347 (JWT signature), CWE-643 (XPath), CWE-644 (header
  injection). Every CWE the codebase references now maps to a framework.

## [2.4.30] — 2026-09-14

### Added — Proof-Obligation Engine (structure by construction)

- New `src/obligations.ts`: append-only obligation ledger — every hypothesis
  is an OPEN proof debt that must be discharged (verified/refuted/blocked).
- New tools: `next_obligation` (single-decision loop: return the top open
  obligation + the exact test), `discharge_obligation` (verified/refuted/
  blocked), `obligations` (ledger + deterministic `complete` gate).
- `engagement_track` (pending) now auto-creates an obligation; `generate_report`
  is GATED — it warns while open proof debt remains.
- System prompt: the LLM drives the engagement as a single-decision loop; it
  holds no plan in its head — the ledger is the single source of truth.

## [2.4.29] — 2026-09-14

### Added — Enterprise compliance mapping (CWE -> frameworks)

- New `src/compliance.ts`: data-driven mapping of 25 web/app CWEs to OWASP
  Top 10 (2021), OWASP ASVS v4.0, PCI DSS v4.0, ISO 27001:2022 Annex A, and
  NIST SP 800-53.
- New `compliance` tool: map a single CWE or an aggregate list.
- `generate_report` now emits a "## 6. Compliance Mapping" section — a CISO/
  auditor can see which controls every finding violates, not just a CVSS.

## [2.4.28] — 2026-09-14

### Added — Enterprise Empirical Intelligence Ledger (LOOP 2, cross-target)

- New `src/intelligence.ts`: append-only JSONL ledger
  (`~/.blitzstrike/intelligence.jsonl`) that records VERIFIED verdicts
  (confirmed/false_positive) as (vector, tech) outcomes — the enterprise
  layer that makes Blitz Strike COMPOUND across engagements.
- `strike_resolve` now auto-records every confirmed/false_positive verdict
  into the ledger (sink type -> attack-vector name via sinkToVector).
- `attack_plan`'s success_probability is now a Bayesian posterior: the formula
  prior is upgraded by the empirical hit-rate (Beta-binomial, prior strength
  K=5), falling back tech-specific -> any-tech -> formula. A new Laravel target
  inherits the hit-rates of past Laravel engagements.
- New `intelligence` tool: query hit-rates / top-vectors / raw ledger.
- System prompt: cross-target intelligence directive.

## [2.4.27] — 2026-09-14

### Added — SELF-HARDENING loop (false-positives -> corpus -> benchmark)

- New `capture_false_positive` tool: records a VERIFIED false positive (code +
  language + detector + note) into a writable corpus (`~/.blitzstrike/corpus/`,
  override `BLITZSTRIKE_CORPUS_DIR`). Every engagement makes the detector more
  precise — never just discard a refuted lead.
- `loadCorpus` now merges the package corpus (read-only) + the captured
  corpus (writable), so the next `run_benchmark` measures whether a captured
  FP is fixed (tn) or still_flagged (fp).
- `run_benchmark` reports a `captured_false_positives` section: total /
  still_flagged / fixed + per-entry outcome.
- System prompt: verified false positives must be captured for self-hardening.

## [2.4.26] — 2026-09-14

### Added — derived success_probability + estimated_time + plan modes

- `attack_plan` now returns, per vector, a DERIVED success_probability
  (relevance prior: clamp(0.85 - 0.15*(priority-1), 0.25, 0.85) — priority 1 =
  0.85 down to priority 4 = 0.40) and estimated_time_sec (from an
  operation-class table: passive/config < injection < deep/manual), plus a
  total_estimated_time_sec.
- New `mode` param: full (all vectors) / quick (priority<=2) / stealth
  (passive/config vectors only) — objective-based planning, DERIVED (not
  hardcoded 0.8/0.9 guesses).
- success_probability is a PLANNING prior, deliberately distinct from the
  evidence-backed confidence (computeConfidence) — documented in the tool.

## [2.4.25] — 2026-09-14

### Doctrine — "if you can continue, why not? if possible, why not try?"

- Added an explicit chain-execution DOCTRINE to the system prompt: a chain
  step you CAN execute is one you MUST execute now. A PREREQUISITE (e.g. a
  CORS->session-theft chain needing "a foothold on any subdomain") is a chain
  step, NOT a "next engagement" — check for dangling DNS / XSS now, don't
  defer it.
- Tightened the completion rule: COMPLETE means every lead verified/blocked
  AND every reachable chain step executed or blocked (no deferred
  escalations); declaring COMPLETE with a reachable chain step deferred is a
  violation.

## [2.4.24] — 2026-09-14

### Fixed — LLM finding-lifecycle loop (opencode "repeated failures")

- `finding_transition` was STATELESS (returned `{legal: bool}` for a status
  string), so an agent calling it to "advance a finding" saw no state change
  and looped, tripping opencode's "Continue after repeated failures" gate.
- Now STATEFUL: pass the full finding JSON + target status and it returns the
  UPDATED finding (detected->triaged->hypothesis->validating->confirmed),
  with the legal next states, a clear "illegal transition" error, and an
  explicit TERMINAL-state hint.
- `confidence_score` response now carries a "deterministic — do not retry"
  note and points to strike_resolve for stateful advancement.
- Added a FINDING LIFECYCLE directive to the system prompt (finding_create ->
  strike_verify -> strike_resolve; never loop stateless tools).

## [2.4.23] — 2026-09-14

### Precision — false-positive reduction + per-detector benchmark

- Fixed 6 false-positive patterns in the heuristic detectors (complex-bugs +
  route-confusion): canonicalized include (`basename`/`realpath`), whitelist
  lookup (`$allowed[$p]`), batch-forwarding WITH an auth re-check, anchored
  validation regex (`preg_match('/^[a-z]+$/')`), constrained SSRF (fixed
  `scheme://` host literal), and URL literals in the path-confusion detector.
- Extended the benchmark to measure per-detector precision/recall/F1 (taint +
  complex_bugs + route_confusion) with 28 new labelled fixtures.
- Corpus now at 137 cases: **precision 1.0 / recall 1.0 / F1 1.0, 0 FP, 0 FN**
  across all three detectors.

## [2.4.22] — 2026-09-14

### Added — on-disk report persistence (reports/ folder)

- `generate_report` now WRITES the HackerOne-grade markdown/JSON report to
  `~/.blitzstrike/reports/<scope-slug>-<timestamp>.md` (override via
  `BLITZSTRIKE_REPORT_DIR`) and returns the saved path — an engagement now
  produces an on-disk deliverable, not just an in-memory string.
- `run_engagement` / `run_autonomous` also persist their inline report to the
  same folder (report.report.saved).

## [2.4.21] — 2026-09-14

### Security — eliminate the last shell-interpolation sites

- `hasCommand` (catalog) + `which` (cli) checked `command -v ${cmd}` with
  `shell: true`. Hardened: the command is now passed as a positional `$1` to
  `sh -c 'command -v "$1"'` — zero user-controlled shell text anywhere.
- Full re-audit: 0 remaining `shell: true` + dynamic/interpolated argument.
  The 8 remaining `shell: true` calls all run STATIC, trusted commands
  (catalog install/check strings), never user input.

## [2.4.20] — 2026-09-14

### Security — command-injection fixes (self-audit)

- CRITICAL: `run_catalog_tool` built a shell string (`args.join(" ")` + `shell: true`)
  from the target — an attacker-controlled target with shell metacharacters
  (`evil.com; rm -rf /`) executed arbitrary commands. Now runs the tool directly
  (`spawnSync(args[0], args.slice(1))`, no shell) — the target is a literal argv.
- MEDIUM: `diff_analyze` / `incremental_scan` / `worktree` interpolated
  user-controlled git refs + branch/path into `execSync` (shell). Now use
  `execFileSync("git", [...])` — no shell interpretation.

## [2.4.19] — 2026-09-14

### Added — unit tests for 5 deep modules + off-by-one fix

- 25 new hermetic checks: chain-executor dispatch (scan/crack/defer), memory
  lifecycle (remember/dedup/lookup/forget), complex-bugs (deserialization /
  type-juggling / mass-assignment / prototype-pollution / SSRF / SSTI / XXE),
  route-confusion (dynamic dispatch/method/include/batch), universal-taint
  (PHP command-injection + sanitizer suppression + language detection).
- Fixed an off-by-one in `detectBatchForwarding`: a single-line
  `foreach (...) { forward(...); }` was missed because the body scan skipped the
  `foreach` line itself.

## [2.4.18] — 2026-09-14

### Fixed — catalog placeholder installs (full audit)

- 3 Go tools that had a placeholder install now install for real:
  cloudfox / ligolo-ng (`go install …@latest`), gophish (`go build`).
- 4 GUI/C2/versioned tools (havoc, ghidra, cutter, velociraptor) + burp-suite-mcp
  are now flagged `installable: false` — bulk-install reports them as "manual
  (install by hand)" instead of failing on a fake "download from github releases".
- `ensureTool` / `ensure_tool` now return `action: manual` + the note for these
  tools instead of attempting the placeholder command.

## [2.4.17] — 2026-09-14

### Added — auto-provision toolchains + non-interactive installs

- Preflight now AUTO-PROVISIONS missing build toolchains (go, cargo, meson, ninja)
  instead of only warning — `install-tools` installs them via apt before the
  mass install, so `go install` / `meson build` / `ninja` no longer fail.
- All install commands now run with stdin closed (non-interactive) — prompts like
  metasploit's "Overwrite? (y/N)" can no longer hang the run; `yes |` is piped
  where an interactive confirm is required.

## [2.4.16] — 2026-09-14

### Added — auto-fallback install (toolchain provision + pip fallback)

- `go install` / `cargo install` tools now auto-provision the missing toolchain
  (`apt-get install golang-go` / `cargo`) before installing — no more
  "go: not found" / "cargo: not found" failures (provisioned once per run).
- `pip install --break-system-packages` now falls back to `pip install --user`
  when the flag is unsupported (pip < 23.0 on older distros) — no more
  "no such option: --break-system-packages".

## [2.4.15] — 2026-09-14

### Fixed — detection → verification loop now unmissable

- `run_engagement` / `run_autonomous` now return `status: DETECTED` (was
  `COMPLETE`), signalling that verification is the NEXT mandatory step instead
  of implying the job is done with unverified hypotheses.
- System prompt adds a hard rule: after detection you MUST `strike_verify` /
  `verify_file_read` / `drive_devtools` each finding before `generate_report`.
- New generic `verify-phase` playbook (read_playbook) — verdict recipe
  (confirmed/false-positive/unconfirmed/blocked), tool mapping, no-babysitting
  rules — so any engagement can load the verify doctrine on demand.

## [2.4.14] — 2026-09-14

### Added — mandatory devtools-MCP precision directive

- System prompt now mandates: when a lead needs DOM/JS precision (DOM-XSS sink
  execution, AJAX interception, JS runtime errors, redirect chains, SSO/token
  flow), the LLM MUST call `drive_devtools` (spawns chrome-devtools-mcp + drives
  a real headless browser) instead of eyeballing static HTML — the precision +
  consistency layer. Includes a `check_mcp` preflight step.

## [2.4.13] — 2026-09-14

### Improved — live install progress

- `install-tools` streams a real-time `[done/total]` counter per tool completion,
  so a long bulk install is visibly progressing instead of appearing stuck.

## [2.4.12] — 2026-09-14

### Improved — install-tools failure diagnostics

- `install-tools` now reports the REASON for every failed tool (last stderr/stdout
  lines) instead of a bare `Failed: …` list.
- Preflight reports missing toolchains (go/java/python/cargo/meson/ninja/make/gcc)
  + the `apt install` line to fix them before the mass install.
- Per-tool install budget raised 120s → 300s so cold-cache `go install` /
  `pip install` of large tools (nuclei, amass, httpx, metasploit, …) no longer
  time out.

## [2.4.11] — 2026-09-14

### Fixed — bulk-install no longer pollutes the caller's cwd

- `install-tools` / `install_all_tools` now run every install command in a fixed
  tools directory (`~/.blitzstrike/tools`, override `BLITZSTRIKE_TOOLS_DIR`), so
  `git clone`-style tools (massdns, phpggc, radare2, testssl.sh, …) no longer
  land in whatever directory you happened to run from.
- Added those cloned tool dirs to `.gitignore`.
- `blitzstrike install` now prints a hint pointing to `blitzstrike install-tools`
  for the full 140-tool catalog.

## [2.4.10] — 2026-09-14

### Added — auto-install external MCP servers to every agent

- chrome-devtools-mcp is now flagged `installable` in the catalog: `install-tools`
  / `install_all_tools` provision it (npm i -g) instead of skipping all MCP
  servers. burp-suite-mcp stays skipped (GUI/daemon — build + run manually).
- `blitzstrike install` (register to every agent) now also auto-installs
  chrome-devtools-mcp so all agents can drive a real browser immediately.

### Fixed — doctor git stderr leak

- `validateRelease` suppresses git/npm stderr, so `blitzstrike doctor` no longer
  prints a stray `fatal: not a git repository` / `No tags can describe` line when
  run outside a git checkout.

## [2.4.9] — 2026-09-14

### Added — evidence-first enforcement (findings are never born empty)

- `makeFinding` + `finding_create` now accept `evidence` at creation — a finding
  can carry its observed artifact (headers/URL/response) the moment it is
  created, instead of relying on a separate attach call that gets skipped.
- `finding_create` warns when a finding is created with no evidence.
- `reportMarkdown` now flags evidence-less findings with an explicit
  "Evidence-first violation" block (ids listed) — detection without proof is
  surfaced instead of silently shipped.

## [2.4.8] — 2026-09-14

### Added — MCP integration health checks

- New `checkMcpServers` (`src/mcp-status.ts`): verifies external MCP
  integrations are actually present/connected — chrome-devtools-mcp (stdio:
  binary or npx auto-install) and burp-suite-mcp (SSE: alive only when Burp is
  running with the extension loaded).
- `blitzstrike doctor` now reports both MCP servers with availability + fix hints.
- New MCP tool `check_mcp` to probe MCP integration status on demand.

## [2.4.7] — 2026-09-14

### Added — deterministic arbitrary-file-read verification (no bare hypotheses)

- New `verifyFileRead` (STRIKE): verifies a CWE-22 / path-traversal / LFI
  hypothesis by reading a marker file (`/etc/passwd`) vs a non-existent
  negative-control path, then comparing. Confirmed only when the marker returns
  file content and the control does not — never from reasoning alone.
- Supports raw POST body (`bodyRaw`) and named query/body param injection.
- New MCP tool `verify_file_read` + chain hints `verify_file_read` /
  `path_traversal` / `lfi` / `file_read` route to it; `strike_verify` now
  auto-routes file-read findings to the file-read verifier.
- A gated endpoint (e.g. identical 500 auth wall) now returns an explicit
  `unconfirmed` verdict with reason instead of leaving a bare hypothesis.

## [2.4.6] — 2026-09-14

### Added — chrome-devtools-mcp auto-install (npx zero-install fallback)

- `drive_devtools` / `browser_devtools` now auto-fetch chrome-devtools-mcp via
  `npx -y chrome-devtools-mcp@latest` when no global binary is present — no
  manual `npm i -g` required. (burp-suite-mcp still can't be auto-installed:
  it's a Java/GUI app that must be built + run manually.)

## [2.4.5] — 2026-09-14

### Added — responsible-disclosure header (X-HackerOne-Research)

- New `H1_USERNAME` env var: when set, every outbound security-testing request
  (STRIKE verification, live recon, active scan, advanced checks, leak-source
  fetch) carries `X-HackerOne-Research: <username>` so targets/triagers can
  identify the researcher.
- `src/http.ts` central helper (`researchHeaders` / `withResearchHeaders` /
  `h1Username`); injected across strike, live-recon, active, orchestrator, server.
- `blitzstrike doctor` now reports the HackerOne research-header status.

## [2.4.4] — 2026-09-14

### Added — automated publishing via npm trusted publishing (OIDC)

- New `.github/workflows/release.yml`: publishes to npm on push to `main`
  (version-gated) using trusted publishing (OIDC) — no npm token, no 2FA.
- Adds `--provenance` (SLSA attestation) so every release is verifiably built
  from this repo. npm's bypass-2FA token deprecation no longer blocks releases.

## [2.4.0] — 2026-09-14

### Added — bulk tool installation (install the whole catalog at once)

- `installAllTools({ category?, concurrency? })` + `ensureToolAsync()`: install
  every non-MCP-server catalog tool in parallel (bounded concurrency), skipping
  MCP servers (they are connected, not installed). Returns installed /
  already_installed / failed + per-tool result.
- CLI: `blitzstrike install-tools` (all), `--category recon` (filter),
  `--concurrency 8` (workers), `--dry-run` (preview without installing).
- MCP tool `install_all_tools` so the driving agent can mass-provision the
  toolbelt instead of ensure_tool one-by-one.

## [2.3.4] — 2026-09-14

### Fixed — CI failure (browser checks threw on missing Chromium binary)

- Root cause: `chromium.launch()` sat OUTSIDE the try/catch in all four browser
  checks, so a clean CI runner (playwright-core installed but no Chromium binary)
  threw an uncaught error → the browser-dispatch unit test failed.
- Added `launchHeadless()` which returns null on launch failure; every browser
  check now degrades to `unavailable` instead of throwing. Verified by running the
  browser dispatch with `PLAYWRIGHT_BROWSERS_PATH=/nonexistent`.

## [2.3.3] — 2026-09-14

### Added — Burp Suite MCP auto-verification (SSE detect + handshake)

- New `src/burp-mcp.ts`: `driveBurpMCP(url)` detects whether the Burp MCP SSE
  server is alive (default http://127.0.0.1:9876/sse), then performs the MCP SSE
  handshake (endpoint event → initialize → tools/list) and returns the server
  info + tool list — or a clear, actionable "start Burp + load the extension"
  error when it is unreachable.
- The `burp` chain hint now auto-verifies: `executeChainSteps` probes the SSE
  endpoint and reports alive/not-alive instead of returning a connect string.

## [2.3.2] — 2026-09-14

### Added — chrome-devtools-mcp auto-verification (Blitz becomes an MCP client)

- New `src/devtools.ts`: a minimal MCP stdio client + `driveChromeDevtools(target)`.
  Blitz now spawns chrome-devtools-mcp, performs the initialize handshake, and
  DRIVES its tools (list_pages → navigate_page → list_network_requests →
  list_console_messages → evaluate_script) against a target, returning live traffic,
  console messages, and a JS eval.
- The `browser_devtools` chain hint now auto-executes: `executeChainSteps` spawns
  and drives a real browser session instead of returning a connect string.
- New MCP tool `drive_devtools` so the driving agent can open any URL in a live
  Chrome and capture network/console/eval on demand.
- Discovers a usable Chromium (system Chrome → playwright cache) and passes
  `--no-sandbox --disable-gpu` for root/container runs.

## [2.3.1] — 2026-09-14

### Fixed — verified both MCP servers live (no more "pajangan")

- **chrome-devtools-mcp** verified end-to-end over stdio: initialize handshake OK,
  `navigate_page` → httpbin 200, `list_network_requests` returns real traffic,
  `evaluate_script` runs JS. Root/container runs crash with "Target closed" unless
  `--chromeArg=--no-sandbox --chromeArg=--disable-gpu` is passed — the `serve`
  string and doctrine now include these.
- **burp-suite-mcp** connection details corrected: it is NOT an npm package / BApp
  store entry — it's a Burp Java extension built via `./gradlew embedProxyJar`
  (→ build/libs/burp-mcp-all.jar), loaded in Burp → Extensions, default SSE
  `http://127.0.0.1:9876`, plus the packaged stdio proxy
  `java -jar mcp-proxy-all.jar --sse-url http://127.0.0.1:9876`.
- Doctrine EXTERNAL MCP SERVERS line now carries the exact, tested commands.

## [2.3.0] — 2026-09-14

### Added — external MCP server integration (chrome-devtools + burp-suite)

- Added `chrome-devtools-mcp` + `burp-suite-mcp` to the catalog (now 141 tools) as
  a new `mcp-server` category. These are discoverable via list_tools, installable
  via ensure_tool, and carry a `serve` connection string.
- `runCatalogTool` detects `mcp-server` entries and returns the connection string
  (npx / Burp extension) instead of spawning a long-running daemon as a one-shot
  subprocess; the chain executor surfaces them as a deferred "connect" step.
- `toolForHint("burp")` now resolves to `burp-suite-mcp` (previously deferred).
- Added an EXTERNAL MCP SERVERS doctrine line so the driving agent knows to CONNECT
  chrome-devtools-mcp (raw network/console/cookie inspection) and burp-suite-mcp
  (proxy + active scanning) for depth the built-in browser can't reach.

## [2.2.4] — 2026-09-14

### Added — browser chain steps auto-execute (no longer deferred)

- Mapped the `browser` / `browser_devtools` chain hints to a finding-level browser
  validation. The executor now drives a real headless Chromium to validate the
  finding (DOM XSS / open redirect / auth bypass / CSRF), choosing the check from
  the finding's class via a data map — the browser tool is the same for every
  chain, only the check type varies.

## [2.2.3] — 2026-09-14

### Added — catalog tools for previously-unresolved chain hints

- Added 9 catalog tools so more chain steps execute instead of deferring to the
  LLM: inql (GraphQL), smuggler (request smuggling), subjs (JS endpoint extract),
  subzy (subdomain takeover), tplmap (SSTI), kubectl, interactsh-client (OOB),
  rogue-jndi (JNDI), ssh. Catalog now 139 tools.
- `toolForHint` now strips ALL non-alphanumerics when matching, so `rogue_jndi`,
  `rogue-jndi` and `roguejndi` resolve to the same tool.

## [2.2.2] — 2026-09-14

### Fixed — interconnection audit bugs

- **runCatalogTool dropped the target for 34 no-required-flag tools** (curl, httpx,
  nmap, dnsx, trufflehog, ...) — the command was built with no target at all. Now
  falls back to an unambiguous target flag (-u/--url/--domain/--target) or a
  positional argument. Extracted `buildCatalogCommand` for deterministic testing.
- **CRLF probe double-encoded** — `encodeURIComponent("%0d%0a…")` produced
  `%250d%250a`, so the CRLF was never injected (permanent false negative). The
  probe is now pre-encoded and sent as-is.
- **Stale run_autonomous note** — still told the LLM to "follow next_steps to
  verify" after the chain executor began auto-executing those steps; updated.

## [2.2.1] — 2026-09-14

### Changed — chain executor is now generic name-based dispatch (no semantic buckets)

- Removed the hardcoded `tool_hint ~ verify/crack/scan` category mapping. The
  executor now resolves each chain step's `tool_hint` by NAME against a Blitz
  finding-tool registry (strike_verify / crack_hash / scan_leaked_source + chain
  aliases), then the external-tool catalog, then manual. Whatever tool the chain
  names for a finding runs — per-target, per-finding, no per-vuln or per-category
  hardcoding.

## [2.2.0] — 2026-09-14

### Added — catalog tool execution (LLM ↔ tools ↔ external tools connected)

- `runCatalogTool(hint, target, extra_flags)` + `toolForHint(hint)`: map a chain
  step's tool_hint (sqlmap, nuclei, jwt_tool, hydra, subfinder, ...) to a catalog
  tool, ensure it is installed (auto-install via ensure_tool), and RUN it against
  the finding's target with the tool's required flags auto-built. Returns exit code
  + capped output. Non-interactive; no destructive flags beyond the tool's own.
- Chain executor now runs catalog-tool hints as a "tool" outcome — a chain step
  that says `sqlmap` executes sqlmap instead of being deferred to the LLM.
- New MCP tool `run_catalog_tool` so the driving agent can run external tools
  directly against a target.

## [2.1.0] — 2026-09-14

### Added — generic chain executor (findings advance through their chain in the pipeline)

- New `src/chain-executor.ts`: `executeChainSteps(finding, steps)` interprets each
  chain step's `tool_hint` and runs the matching deterministic operation, so the
  PIPELINE executes a finding's escalation chain instead of leaving it as a
  hypothesis for the LLM. Target-agnostic: works for SQLi, SSRF, SSTI, LFI, JWT,
  deserialization, etc.
  - `tool_hint ~ verify` → strike_verify (marker + negative control) → confirmed/blocked
  - `tool_hint ~ crack` → crack_hash on any hashes in the finding's evidence
  - `tool_hint ~ scan` → scan_leaked_source on the finding's evidence text
  - otherwise → flagged `deferred` with the exact action + tool
- `run_autonomous` now executes the chain steps for every finding and attaches
  `escalation.executed` (one result per step) alongside the `next_steps`.

## [2.0.0] — 2026-09-14

### Added — full-power attack-vector expansion (JWT / CRLF / host-header / origin bypass)

- **JWT alg-confusion check** — detects JWTs in cookies/headers/body, tests
  alg:none acceptance (signature stripped), and flags RS/ES → HS256 confusion
  candidates.
- **CRLF / header-injection check** — injects `%0d%0aX-BlitzStrike: injected` into
  redirect/url/next/state/token params and flags any reflected header.
- **Host-header injection check** — sends an attacker Host and detects reflection
  in Location / Set-Cookie / body.
- **Origin-exposure flag (direct-to-origin bypass)** — live_recon now classifies
  every resolved host/IP against known CDN ranges (Cloudflare/CloudFront/Fastly/
  Akamai/DDoS-Guard/Imperva) and surfaces `origin_exposed` + a next_step for
  `--resolve` direct-to-origin testing (WAF/CDN layer evaporates).

## [1.19.4] — 2026-09-14

### Fixed — engagement model: recon is input, not the deliverable

- Added a DELIVERABLE + PERSISTENCE doctrine: the deliverable is a HackerOne-grade
  FINDING report (generate_report), never a hand-written recon/surface map; verify
  every lead (strike_verify marker+control / browser_validate) before it becomes a
  finding; a hard block (Cloudflare/WAF/IP/captcha) is NOT the end — mark it
  blocked + note the required vantage, then continue to the next lead; keep trying
  every lead until verified or blocked, THEN generate_report.
- generate_report description now states it is the FINAL deliverable and enumerates
  the full HackerOne-grade section layout.

## [1.19.3] — 2026-09-14

### Fixed — full interconnection audit (no dead/orphan layer)

- Added a KNOWLEDGE BASE line to the MCP instructions so the driving agent can
  discover every layer on demand: skillLookup/listSkills (40 skills),
  list_attack_vectors/attack_vectors (34-category taxonomy), taxonomy(kind)
  (OWASP/CWE/ASVS/API-top-10), read_playbook (17), list_manuals/read_tool_manual
  (317). Verified end-to-end: 97 tools → 35 data functions → 26 data files; 40
  skills loadable; 53 techniques, 57 chains, 18 chain_links, 588 vectors all
  resolve.
- Fixed taxonomy CWE lookup: `taxonomy("cwe", "89")` now matches CWE-89 (query
  normalized to the bare number).

## [1.19.2] — 2026-09-14

### Fixed — sink scan now fires on EVERY response, not just detected probes

- `probeWithBypass` scans every response for leaked sinks regardless of whether
  the specific injection was detected — an SSTI/SSRF/XSS probe that hits a 500
  traceback now still captures the eval()/SECRET_KEY/requests.get sinks it
  reveals. Sink collection was also moved BEFORE the detection early-return so a
  non-detecting probe still contributes its leaked sinks.
- `strike_verify` now returns a `leaked_sinks` field — the baseline/marker/
  control responses are scanned for tracebacks and any revealed sink is attached
  to the verdict.

## [1.19.1] — 2026-09-14

### Fixed — sink enumeration now deterministic (not eyeball-dependent) + no-babysitting hardening

- `probeWithBypass` now scans every error/traceback response for sinks and
  `runAdvancedChecks` turns each distinct sink into its own hypothesis Finding.
  An SQL-error traceback that also shows `eval()` + `SECRET_KEY` + `requests.get`
  now yields an RCE finding + a credential finding + an SSRF finding
  automatically — the driving agent no longer has to notice them by hand.
- No-babysitting rule hardened: "say the word / want me to pursue / should I
  continue" are explicit hard violations — execute the full chain until COMPLETE.

## [1.19.0] — 2026-09-14

### Added — generalized leaked-source sink scan + deterministic hash cracking

- `scan_leaked_source` tool + `sinks.ts`: scan ARBITRARY leaked text (any 500
  traceback, debug page, source dump, config, error message, credential dump)
  for dangerous sinks — eval/exec/os.system/subprocess (RCE),
  render_template_string (SSTI), SQL string-building, requests.get (SSRF),
  file read (LFI), SECRET_KEY/API keys, hardcoded creds, pickle/unserialize,
  XML parse (XXE). Each hit returns the line, snippet, and next action. Not
  Werkzeug-specific — works on any leak.
- `live_recon` now auto-scans the root response for source leaks and attaches
  the enumerated sinks to the recon output.
- `crack_hash` tool + `hash.ts`: identify the hash type and immediately try a
  built-in common-password list offline, then return the exact hashcat/john
  command for a full crack — so "crack the hashes" becomes an action, not a
  recommendation.
- Doctrine: "a 'next chain' you write is a TODO — run it, never leave it as a
  recommendation" (scan_leaked_source / crack_hash as the execute-now tools).

## [1.18.1] — 2026-09-14

### Fixed — Werkzeug skill over-fixated on the PIN, missing the easier RCE path

- The Flask debug skill previously led with PIN derivation, which caused the
  driving agent to get stuck on "one PIN away" and miss the SOURCE-DISCLOSURE
  path (every 500 leaks app source → read it → find eval()/SECRET_KEY/hardcoded
  creds → exploit directly). Reordered: source-disclosure is now Path 1 (read
  the leaked source line-by-line, run blitz_file/taint_file on it), PIN is
  Path 2. Doctrine updated to match.

## [1.18.0] — 2026-09-14

### Added — Werkzeug debug console PIN derivation (RCE follow-through)

- New skill `bs-flask-debug-rce` + technique class `flask_debug_pin`: when the
  LLM finds a PIN-locked Werkzeug/Flask debug console it now derives the PIN
  (deterministically computed from username + modname + app name + mod_path +
  MAC-decimal + machine-id) instead of stopping at "one PIN away from RCE".
  Includes the full SHA1 algorithm, a brute-force matrix for unknown bits, and
  marker + negative-control verification.
- Flask framework tricks now note the PIN-derivation chain.
- Doctrine hardened: "EXECUTE follow-ups NOW, not as next phase" — debug console
  → derive the PIN, dumped hashes → crack/reuse, hidden-content IDOR → test the
  direct route.

## [1.17.2] — 2026-09-14

### Fixed — SSRF false positives + fuller chain composition

- The fetch-reflect SSRF probe used `http://example.com/` → "Example Domain",
  which matched the target's own content (23 false-positive CRITICALs on
  example.com). Now uses a unique canary
  (`http://httpbin.org/anything/blitzstrike-ssrf-canary`) so only a real
  server-side fetch reflects it.
- Escalation mapping now points each chainId at the richer composition chain
  (more steps + a `leads_to` entry): ssti→ssti_to_full_rce,
  deserialization→deserialization_to_rce, path_traversal→
  path_traversal_to_credential_theft, idor→idor_to_admin_takeover,
  open_redirect→open_redirect_to_oauth_theft.

## [1.17.1] — 2026-09-14

### Fixed — chain escalation was silently broken + restored chain-aware doctrine

- `run_autonomous` escalation lookup was broken: a finding's `chain_id`
  (e.g. `sql_injection`) never matched the chains.json ids (e.g. `sqli_to_rce`),
  so every finding's `escalation` was null. Added a chain-id mapping and now
  attach the escalation chain (steps + tools) AND a `leads_to` composition
  (from chain_links.json) — e.g. SQLi → `sqli_to_hash_dump_and_crack` +
  `path_traversal_to_credential_theft`.
- Restored a compact "CHAIN DECISIONS" doctrine to the MCP instructions: a
  confirmed finding is the START, not the end — enumerate ESCALATE / CHAIN /
  BYPASS / PIVOT follow-ups and ask "I found X → what can I now read/do/access?"
  (SQLi → query for creds + console PIN + source), verifying each follow-up.

## [1.17.0] — 2026-09-14

### Added — attack_plan (data-driven attack-vector decisions)

- New `attack_plan(target, tech, params)` tool: turns recon context (detected
  tech + discovered params) into a prioritized list of attack vectors to test,
  each with a reason and the specific tool. Base injection vectors are always
  listed; param hints (id→idor/sqli, url→ssrf/redirect, cmd→command-injection)
  and tech hints (wordpress/laravel/flask/spring/...) add and reprioritize.
- The MCP instructions now point to `attack_plan` as the way to "decide what to
  test next" — the driving agent enumerates the full vector surface with data
  instead of guessing a few checks.

## [1.16.0] — 2026-09-14

### Added — more injection vectors (command injection + real XSS + fetch-reflect SSRF)

- **Command injection (CWE-78)** — new advanced check: injects `; id` into 14
  command-ish params (cmd/command/exec/run/ping/host/ip/file/path/...) and flags
  a hit on `uid=`/`gid=`/`www-data`/shell output.
- **Reflected XSS (CWE-79)** — now tests REAL payloads, not just a random
  marker: `<script>alert(document.domain)</script>` (script context) and
  `"><img src=x onerror=alert(1)>` (attribute breakout), flagging UNESCAPED
  reflection. The previous reflected-input sweep only detected reflection, not
  whether XSS was actually possible.
- **SSRF** — added a second probe (`http://example.com/` → "Example Domain") to
  catch fetch-reflect SSRF, and expanded the param list (fetch/download/import/
  feed/source/load/next).
- writeup engine + report now carry command-injection and XSS impact/remediation.

## [1.15.1] — 2026-09-14

### Changed — every finding now carries a full CVSS v3.1 vector

- The report emits a complete CVSS v3.1 vector string (e.g.
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) alongside the score. When a
  finding has no explicit CVSS, a severity-band metric set is used to compute
  both score and vector, so the detailed-findings table always shows the vector.

## [1.15.0] — 2026-09-14

### Added — HackerOne-grade report generation

- New `writeup` engine (`src/writeup.ts`) turns every finding into the prose a
  professional report needs: description, root cause, numbered reproduction
  steps, impact, remediation, and references — pulling structured content from
  the technique knowledge base (summary + how_to_test) and the finding's own
  CWE/severity/chain.
- `reportMarkdown` rewritten to a full assessment-report format: Executive
  Summary, Scope, Methodology, Summary of Findings table, per-finding detailed
  sections (severity/CVSS/CWE/status/confidence + description + root cause +
  reproduction + impact + remediation + references), Recommendations, and an
  Appendix (unverified hypotheses + cleared false positives).
- CVSS falls back to a severity-band default (critical 9.8 / high 8.1 / medium
  6.1 / low 3.1) when a finding has no explicit CVSS, so the report never shows
  a bare "—".

## [1.14.1] — 2026-09-14

### Fixed — LLM wasn't reliably reaching for tools (instructions were a 14KB manual)

- MCP `instructions` shrunk 13,989 → 1,720 chars. The old text was a full
  methodology manual; smaller driving models (e.g. GLM) drowned in it and missed
  the one directive that matters. Now the FIRST lines are the actionable trigger:
  "user says test/scan/audit → call run_engagement FIRST", followed by the
  non-negotiable rules. Detailed methodology stays in the skills (loaded
  on-demand via read_skill).
- `run_engagement` / `run_autonomous` descriptions now lead with the trigger
  ("the DEFAULT first call when the user asks to test/scan/audit") instead of a
  weak "prefer this".

## [1.14.0] — 2026-09-14

### Fixed — live pipeline timeout (parallelized request trees)

- The full live engagement was exceeding the 120s MCP tool timeout because every
  request was sequential. Now parallelized:
  - `dnsBrute` (51 lookups), `scanPorts` (26 probes), `discoverApi` (14 paths)
    run concurrently via `Promise.allSettled`.
  - Passive recon phases (subdomains / DNS / Wayback / API) run in parallel.
  - Reflected sweep (9 params), deterministic checks (open-redirect + traversal),
    and advanced checks (SSTI/SSRF/SQLi — 40 params) all run in parallel.
  - Wayback CDX timeout 60s → 25s.
- `run_engagement` on a live URL now completes in ~15-20s instead of timing out.

## [1.13.2] — 2026-09-14

### Fixed — OpenCode connection + server version reporting

- `opencodeWrite` now writes the RESOLVED command (global `blitzstrike` binary
  first, npx only as fallback) instead of hardcoding `npx -y blitzstrike`, which
  could pull a stale npm-registry version. A locally-installed build is always
  preferred.
- MCP `serverInfo.version` now reports the real package version (was hardcoded
  "1.0.0"), so a driving agent can see exactly which build it is talking to.

## [1.13.1] — 2026-09-14

### Changed — cross-agent consistency (100% one doctrine)

- Rewrote the OpenCode orchestrator persona (`opencode-agents/Blitz Strike.md`)
  and fixed `Strike.md` — removed the stale scope/authorization gate language
  ("approval gate", "authorize=true", "authorized targets only", "ask before
  proceeding") so every persona now matches the MCP instructions: scope is
  intel-only, no authorization gate, `run_engagement` = FIRST + ONLY action,
  WAF bypass is automatic.
- Portable persona (AGENTS.md / CLAUDE.md / SKILL.md) synced to the same
  doctrine + added the scope/WAF-bypass section.
- MCP instructions now state that `strike_verify` + live checks AUTO-attempt WAF
  bypass (do not report "needs WAF bypass" without re-probing).

## [1.13.0] — 2026-09-14

### Added — WAF-bypass-aware verification

- `strike_verify` now detects a WAF block (403/406 or a block-page signature —
  "Akses Dibatasi" / F5 / Cloudflare / ModSecurity / etc.) and, instead of
  declaring "unconfirmed", retries the marker through 6 evasion variants
  (double URL-encode, case variation, HTML entity, inline comment split,
  separator, null byte). A variant that reflects the original marker = confirmed
  with the bypass technique recorded.
- The advanced live checks (SSTI / SSRF / error-based SQLi) now use the same
  bypass re-probe, so a WAF-gated injection is actually tested rather than
  reported as "needs WAF bypass".

## [1.12.0] — 2026-09-14

### Changed — scope is intel-only (never a gate)

- `scope_check` / `active_scan` / `run_engagement` no longer refuse a URL for
  lack of scope. Scope is classified (in_scope / out_of_scope / not_in_scope /
  unscoped) and recorded for the report, but `allowed` is always true — the repo
  disclaimer carries responsibility (exactly like nmap/sqlmap/Burp).
- Routing doctrine hardened: when the user says "test / scan / audit / pentest",
  the FIRST and ONLY action is `run_engagement` (or `run_autonomous`) — never a
  manual live_recon/blitz_scan first, never a fallback to manual probing.

## [1.11.2] — 2026-09-14

### Changed — live_recon result caps lifted

- Response body cap 50KB → 500KB (no longer truncates large HTML/sitemap/crt.sh
  responses, so no links/endpoints/certs are silently dropped).
- Wayback CDX limit 500 → 10000 historical URLs.
- DNS subdomain display cap 8 → 50 in next_steps.

## [1.11.1] — 2026-09-14

### Fixed — live engagement friction (scope wildcard + timeout recovery)

- Scope matching now handles `*.host` wildcards correctly (apex + subdomains,
  and no loose substring false matches). Previously `*.vuln-web-app.onrender.com`
  failed to match the apex host, forcing a retry loop.
- Added a `timeout` recovery mode to `retry_guidance` (slow/free-tier targets:
  split into lighter probes, add explicit scope, target one endpoint, retry
  after cold-start).

## [1.11.0] — 2026-09-14

### Changed — no-babysitting doctrine wired into an autonomous loop

- Added an explicit AUTONOMOUS LOOP to the MCP instructions: plan → run_autonomous
  → delegate → task checkpoint/resume → watchdog → context_prune → terminate.
  No-babysitting is now GUARANTEED by the interconnected tools (code-driven), not
  just by a "never ask" prompt.
- Fixed the one remaining contradiction: the DAST skill said "always confirm with
  the user"; aligned it to the destructive-consent pause condition (the only
  consent pause; non-destructive steps proceed autonomously).

## [1.10.0] — 2026-09-14

### Fixed — live pipeline false positives (hypothesis is not a finding)

- SSTI detector used the weak marker `{{7*7}}` → `49`, which matched "49"
  appearing randomly in any HTML page (12 false-positive "Critical" on a clean
  target). Switched to the distinctive `{{7*'7'}}` → `7777777` evaluation.
- Reflected-input sweep reported every tested parameter as a finding even when
  the marker was NOT reflected (9 noise "unconfirmed" findings). Now only a
  CONFIRMED reflection is a finding; negative results are tracked separately
  in `report.tested`.

## [1.9.0] — 2026-09-14

### Fixed — manuals data layer not bundled in npm tarball

- `manuals-index.json` was missing from the package `files` list, so
  `list_manuals` / `read_tool_manual` / `read_playbook` returned empty from an
  npm install (the 317 manuals + 17 playbooks were not indexed). Added the
  index file to the tarball. Also added a data-layer smoke test
  (`test/data-smoke.ts`) covering every runtime data file (30 checks).

## [1.7.1] — 2026-09-14

### Fixed — npm publish (dist-tag + staged-version)

- Republish with the `latest` dist-tag corrected (previous publishes left
  `latest` pinned to 1.0.95) and a clean tarball (1.6.0/1.7.0 were stuck in a
  staged state).

## [1.7.0] — 2026-09-13

### Added — advanced deterministic checks (live + source)

- Live pipeline: `run_engagement` now also runs advanced deterministic checks —
  SSTI (`{{7*7}}` → `49`), SSRF (cloud metadata reflected through a URL param),
  and error-based SQLi (SQL error signature) — on top of the standard
  reflected/header/redirect/traversal/CORS sweep.
- Source pipeline: `complex_scan` grows from 6 to 9 detectors — added SSRF
  (user-controlled URL with no host allowlist), XXE (user XML parsed without
  disabling entities), and SSTI (user input into a template render), each with
  a defense-suppression check (allowlist / libxml_disable_entity_loader /
  basename).

## [1.6.0] — 2026-09-13

### Added — task checkpoint journal (per-workstream resume)

- Four new ORCHESTRATION tools for resilient delegation:
  - `task_start` — register a workstream with an ordered plan (steps).
  - `task_checkpoint` — record a checkpoint per step (in_progress / done /
    failed / blocked) with an optional note + output hash.
  - `task_status` — read the current step, progress (done/total), remaining
    steps, and full checkpoint history.
  - `task_resume` — compute the resume instruction: last completed checkpoint,
    current step, remaining steps, and the exact re-dispatch prompt.
  On-disk, so a failed workstream resumes from its last completed step instead
  of restarting from scratch.

## [1.5.0] — 2026-09-13

### Added — run_autonomous (self-driving orchestrator with escalation)

- New `run_autonomous` tool: the surface pipeline (run_engagement) + the
  escalation path pre-attached to every finding. Each finding comes back with
  its chain (name/severity/prerequisites) and ordered `next_steps` (action +
  tool_hint + success_criteria + negative_control) so the LLM never guesses
  what to do next. Returns a deterministic termination reason (no_new_signal /
  max_passes) and the full report.

## [1.4.0] — 2026-09-13

### Added — autonomous orchestration ops (planning / delegation / worktree / watchdog / prune)

- Five new ORCHESTRATION tools for autonomous driving:
  - `plan` — deterministic engagement phase plan + next action (the planning
    pass; call once at the start).
  - `delegate` — decompose a workstream list into parallel-first subagent
    dispatch batches (named dependencies only) + the no-retry-cap retry pattern.
  - `worktree` — create/list/remove an isolated git worktree so parallel
    workstreams don't conflict on the same files.
  - `watchdog` — detect a stalled phase (idle > 15 min, no hypotheses) and
    return the concrete intervention.
  - `context_prune` — compact the engagement state so the LLM can drop raw
    detail and keep only the summary.

## [1.3.0] — 2026-09-13

### Added — deterministic live security checks (deeper one-call pipeline)

- `run_engagement` on a URL target now runs deterministic checks beyond the
  reflected-input sweep: missing security headers (HSTS/CSP/X-Frame-Options/
  X-Content-Type-Options/Referrer-Policy), open redirect (Location reflection),
  path traversal (`../../etc/passwd` → `root:`), and CORS (reflected/wildcard
  origin + credentials). Each is a pure HTTP observation, so the one-call live
  audit covers 5 vuln classes with zero false positives on header checks.

## [1.2.2] — 2026-09-13

### Changed — changelog wording cleanup (no functional change)

## [1.2.1] — 2026-09-13

### Fixed — resolve routing ambiguity (no "or", decide the default)

- Routing doctrine now states the DEFAULT explicitly: prefer `run_engagement`
  (one call) for a whole engagement; drive `live_recon`/`blitz_scan`/
  `strike_verify` manually only for targeted follow-up on a specific finding.
- Fixed a stale instruction description ("autonomous live marker sweep" →
  "full autonomous live pipeline: recon + marker/negative-control sweep").

## [1.2.0] — 2026-09-13

### Added — deterministic full live pipeline (no-babysitting)

- `run_engagement` on a URL target now runs the FULL autonomous live pipeline in
  one deterministic call: `live_recon` (fingerprint, WAF, tech, crawl,
  subdomains, DNS, API discovery, intel, next_steps) + marker/negative-control
  reflected-input sweep + inline report. The LLM no longer drives recon →
  analyze → verify step-by-step; a single call maps the whole surface and
  verifies reflections. The server-side orchestrator (not the LLM) drives the
  flow, so it cannot stall to ask the user.

## [1.1.7] — 2026-09-13

### Improved — no-babysitting doctrine hardened (3 precise pause conditions)

- Pause conditions now precise (3): destructive/DoS needs consent, external
  dependency beyond control blocks (e.g. phone OTP), or engagement complete.
- Added "no retry cap" (diagnose + resume until verified, never move on
  unverified) and "parallel by default" (fire all independent workstreams in
  one message; only named input/file-conflict dependencies are sequential).

## [1.1.6] — 2026-09-13

### Fixed — never ask "should I continue?" (no-babysitting)

- Doctrine now explicit: NEVER ask "should I continue?" / "do you want me to
  stop?" — continue autonomously to the end. Surface to the user ONLY when a
  genuinely destructive/DoS action needs consent, or the engagement is complete
  (final report). Removed "target is ambiguous" as a mid-engagement pause reason.

## [1.1.5] — 2026-09-13

### Expanded — full Awesome-Hacking resource index (78 entries, 44 domains)

- `resources.json` expanded from 30 (web/pentest subset) to 78 entries covering
  every domain in the Awesome-Hacking meta-list: web, api, pentest, recon,
  payload, cve, privesc, source, fuzzing, llm, framework, osint, rev, cracking,
  forensics, malware, ir, intel, cicd, devsecops, defense, knowledge, labs, ctf,
  mobile, iot, ics, vehicle, drone, cellular, rtc, mainframe, rf, physical,
  social, web3, crypto, exploit, network, tool, ... — each tagged with use_when.

## [1.1.4] — 2026-09-13

### Added — OWASP Web Top 10 + ASVS (complete taxonomy)

- `taxonomy` tool now serves four standards: OWASP Top 10 2021 (web), OWASP API
  Security Top 10 2023 (api), CWE mapping (cwe), and ASVS verification chapters
  (asvs) — each mapped to Blitz Strike coverage.
- New `intelligence/owasp_top10.json` (A01–A10) + `intelligence/asvs.json`
  (V1–V14).
- doctrine_map cross_cutting + RESOURCE MAP + `bs-web-hunting` now reach
  `taxonomy` and `resource_lookup` for full no-babysitting interconnection.
- THIRD-PARTY-NOTICES: OWASP Top 10 + ASVS (CC BY-SA 4.0).

## [1.1.3] — 2026-09-13

### Added — standard taxonomy (OWASP API Top 10 + CWE)

- New `taxonomy` MCP tool + `intelligence/api_top10.json` + `cwe_map.json`:
  - `taxonomy(api)` → OWASP API Security Top 10 (2023) risks mapped to Blitz
    coverage (BOLA, broken auth, BOPLA, resource consumption, BFLA, business
    flows, SSRF, misconfiguration, inventory, unsafe consumption).
  - `taxonomy(cwe, query)` → CWE ID + name for any technique class (52 mapped),
    for grounding findings in standard IDs during reporting.
- THIRD-PARTY-NOTICES: OWASP API Security (CC BY-SA 4.0) + MITRE CWE.

## [1.1.2] — 2026-09-13

### Added — curated security resource index

- New `resource_lookup` MCP tool + `intelligence/resources.json`: 30 curated
  domain-specific security resources (from the community Awesome-Hacking
  meta-list, filtered to web/pentest relevance) — each tagged with use_when
  (which phase/context it serves). Search by category (web, pentest, bug_bounty,
  api, recon, payload, cve, privesc, source, fuzzing, llm, framework, osint,
  rev, cracking, forensics, malware, ir, intel, cicd, knowledge, labs) or
  keyword. Lets the LLM find the best domain-specific tools/knowledge when
  Blitz Strike's own data doesn't cover a domain.

## [1.1.1] — 2026-09-13

### Added — HackTricks full enrichment (52 classes + 16 frameworks)

- `techniques.json` expanded 25 → 52 vulnerability classes (added crlf, ldap,
  xpath, xslt, ssi, xssi, email injection, formula/CSV injection, orm, rsql,
  json/xml/yaml, unicode, dangling markup, account takeover, 2FA bypass,
  rate-limit bypass, password reset, captcha bypass, registration, payment
  bypass, timing attacks, uuid insecurities, reverse tabnabbing, iframe traps,
  cookie hacking, postMessage vulnerabilities, methodology).
- New `framework_tricks` MCP tool + `intelligence/framework_tricks.json`: 16
  frameworks (Laravel, Django, Flask, Node/Express, Next.js, Vue, Angular,
  WordPress, Joomla, Spring, JSP, Python, Go, Ruby/Rails, Perl, GraphQL) with
  detection signals, known vulns/CVEs, and concrete attack tricks.
- Synthesized in own words from public technique references (paraphrased, not
  verbatim — HackTricks has no open license).

## [1.1.0] — 2026-09-13

### Added — detailed technique base (25 vulnerability classes)

- New `technique_lookup` MCP tool + `intelligence/techniques.json`: 25 detailed
  vulnerability classes (ssrf, request smuggling, cache poisoning, race
  conditions, ssti, deserialization, prototype pollution, mass assignment,
  sql/nosql injection, xss, cors, csrf, jwt, oauth, host header, open redirect,
  subdomain takeover, idor, graphql, websocket, file upload, path traversal/LFI,
  command injection, xxe). Each class carries summary, objectives, how-to-test
  steps, concrete techniques/tricks, and verify (marker + negative control).
  Synthesized from OWASP WSTG taxonomy + general security knowledge.
- RESOURCE MAP + `bs-web-hunting` cross-references now reach `technique_lookup`.

## [1.0.99] — 2026-09-13

### Added — WSTG + HackTricks enrichment (interconnected doctrine)

- New `wstg_map` MCP tool + `intelligence/wstg_map.json`: maps every OWASP
  WSTG category (12) to the Blitz Strike skill/phase/tools/data that covers it,
  including the high-value advanced tests (smuggling, SSRF, SSTI, deserialization,
  prototype pollution, mass assignment, path confusion, GraphQL, WebSockets).
- `bypass_techniques.json` auth category enriched with concrete 401/403 bypass
  techniques (verb fuzzing, proxy-header spoofing, path normalization, API
  version confusion, JSON parameter pollution, protocol/host confusion).
- `bs-web-hunting` SSRF ladder gained DNS-rebinding-vs-safe-url-checks note.
- THIRD-PARTY-NOTICES: added OWASP WSTG (CC BY-SA 4.0).

## [1.0.98] — 2026-09-13

### Added — interconnected doctrine map

- New `doctrine_map` MCP tool + `intelligence/doctrine_map.json`: the
  interconnected doctrine — each phase (scope→recon→analyze→deep→verify→report)
  maps to its skill, OWASP WSTG category, tools, and data, plus cross-cutting
  "reach at the moment" rules (blocked→bypass_lookup, finding→list_chains/
  chain_links, probe→payload_lookup, failed→model_fallback/retry_guidance,
  done→engagement_status).
- `bs-web-hunting` gained a "Related doctrine" section; `bs-orchestrate-
  engagement` now loads both `orchestration` and `doctrine_map`.

## [1.0.97] — 2026-09-13

### Removed — the authorization gate (disclaimer owns responsibility)

- Scope is now recorded, not gated. `scope_check` is intel for the report;
  `active_scan` / `live_recon` / `run_engagement` no longer block on
  `allowed`/`authorize` — they run the target you are given (like nmap/sqlmap/
  Burp, which don't ask). The repo disclaimer carries the responsibility.
- The one hard stop remains: malicious/third-party infra ("cari pelaku") →
  hold/static, never live-probe.
- Updated `bs-scope-gate`, `bs-orchestrate-engagement`, `instructions`,
  tool descriptions, and the removed gate logic in `active.ts`/`orchestrator.ts`.

## [1.0.96] — 2026-09-13

### Added — advanced web live hunting doctrine, separated from source audit

- New `bs-web-hunting` skill: advanced LIVE web bug hunting — deep recon (JS
  maps, parameter mining, versioned APIs, exposed config), advanced injection
  (HTTP request smuggling, cache poisoning/deception, SSRF bypass ladder, race
  conditions, deserialization gadget chains, SSTI filter bypass, prototype
  pollution), advanced auth (JWT key confusion, OAuth redirect, host-header
  poisoning), client-side (CORS/CSP/open-redirect), API (GraphQL/WebSocket/
  IDOR), and the chain mindset — all still gated by marker + negative control.
- Routing now separates the TWO doctrines explicitly: live web/API →
  `web-hunting`; source tree → `source-audit`. The LLM never mixes them.
- Scope relaxed: authorize ONCE, then hunt aggressively (no re-asking each
  step); unauthorized targets are still refused.

## [1.0.95] — 2026-09-13

### Added — three new complex-bug detectors (deepen the moat)

- `complex_scan` now detects six classes (was three), adding:
  - **prototype pollution** — unsafe merge/extend of request data into an object
    without a `__proto__`/`constructor.prototype` guard (Node/JS).
  - **CRLF / header injection** — user input into `header`/`setHeader`/
    `writeHead` (response splitting, cookie poisoning).
  - **path confusion** — user input into a file path with no nearby
    canonicalization (`basename`/`realpath`/`normalize`), catching `..%2f`,
    backslash, and null-byte variants that evade a naive `../` filter.
- Widened `SOURCE_TOKENS` to cover `req.headers`/`req.cookies`/`request.body`.
- `complex_scan` and the `instructions` now name all six classes.

## [1.0.94] — 2026-09-13

### Added — model fallback (mature: classify → decide, not blind fallback)

- New `model_fallback` MCP tool + `intelligence/model_fallback.json`: classifies
  a model/sub-agent failure into 10 classes, each with a retryable + backoff
  flag and a per-class action (retry with exponential backoff / fall back /
  shrink scope / fix credentials / abort), plus a fallback chain that forbids
  downgrading to a weaker model and an explicit backoff schedule.
- More mature than a naive "fall back on any error": quota/auth/permission are
  non-retryable (fix, don't retry); rate-limit/timeout/5xx are retryable with
  backoff; context-length means shrink, not retry.
- `retry_guidance` model_failed and the PERSISTENCE doctrine now route model
  errors through `model_fallback`.

## [1.0.93] — 2026-09-13

### Added — catalog usage trigger

- RESOURCE MAP gained a "CATALOG" entry: Blitz Strike's OWN tools find +
  verify; the 130-tool catalog (sqlmap, nmap, nuclei, ffuf, ysoserial) is for
  deeper EXTERNAL exploitation — run `tool_lookup` → `ensure_tool` →
  `read_tool_manual` after your own analysis confirms a finding.
- Fixed the stale manual count in `read_tool_manual` (270+ → 317).

## [1.0.92] — 2026-09-13

### Added — incremental_scan (wired the last unwired module)

- Full interconnection audit: every module, data file, tool, skill, and manual
  is now referenced. Wired the previously test-only `incremental.ts` into the
  new `incremental_scan` MCP tool (git diff → changed files → full taint +
  data-flow pass, for CI). Zero dead exports, zero orphan source files, all 10
  intelligence data files loaded.

## [1.0.91] — 2026-09-13

### Fixed — naive/inconsistent doctrine content

- Corrected the stale chain count in the RESOURCE MAP (`list_chains (36)` →
  `57`, matching the supporting-layers note).
- Softened "a low-severity finding usually escalates" → "may escalate — check,
  do not overclaim" (not every low-severity finding escalates).
- Fixed the `fofa_search` label (`CVE + asset` → `CVE lookup + asset`, with
  `nvd_lookup` as the CVE lookup).
- `guidance.ts`: "highest-impact claim" → "high-impact claim" (no bug-class
  ranking).

## [1.0.90] — 2026-09-13

### Fixed — prioritization is derived, not hardcoded

- Replaced the naive "RCE/auth-bypass/data-leak first" prioritization with a
  universal rule: order by severity computed deterministically via
  `cvss_score` (impact × exploitability) and weighted by escalation potential
  (`chain_links`) and engagement context — never by bug class. A critical
  stored XSS that yields account takeover outranks an unreachable blind RCE.

## [1.0.89] — 2026-09-13

### Added — professional judgment doctrine

- MCP `instructions` gained a "PROFESSIONAL JUDGMENT" block and
  `bs-orchestrate-engagement` a matching rule: prioritize by impact ×
  exploitability, recognize dead ends and move on, live-test with care
  (respect rate limits, no account lockout / DoS, smallest proof payload), and
  stop at the termination criteria. Closes the "senior tester" layer on top of
  the rigorous process.

## [1.0.88] — 2026-09-13

### Added — hypothesis expansion doctrine (findings → follow-ups)

- `bs-orchestrate-engagement` gained a "Hypothesis expansion" section, and the
  MCP `instructions` a matching "HYPOTHESIS EXPANSION" block: from each finding
  or sink, enumerate every follow-up (escalate via list_chains/chain_links,
  chain via chain_links, bypass via bypass_lookup, pivot to new endpoints) —
  and turn each into a verified or rejected verdict before reporting.
- Codifies the anti-speculation rule: "might/could/possibly" belong in the
  hypothesis list, never in the report; every report line is a verified fact.

## [1.0.87] — 2026-09-13

### Added — engagement state (deterministic orchestration bookkeeping)

- New `engagement.ts` module + 4 MCP tools: `engagement_start` (open an
  engagement), `engagement_phase` (advance the lifecycle phase),
  `engagement_track` (record each hypothesis as pending/confirmed/rejected),
  `engagement_status` (deterministic "am I done?" — returns the exact unmet
  termination criteria instead of a feeling).
- This is Blitz Strike's own orchestration-state answer: the LLM is the brain;
  these tools are the hands that keep the phase + hypotheses + termination
  state so the LLM never relies on its own memory for progress or completion.
- `bs-orchestrate-engagement` documents the track-state loop.

## [1.0.86] — 2026-09-13

### Added — orchestration framework (`orchestration`)

- New `orchestration` MCP tool + `intelligence/orchestration.json`: the
  engagement lifecycle (6 phases — scope → recon → analyze → deep → verify →
  report, each with entry/exit criteria), the sub-agent team (4 roles with
  tools + deterministic output contract), the handoff contract, and termination
  criteria. The driving LLM loads it at engagement start instead of improvising.
- RESOURCE MAP leads with `orchestration()`; `bs-orchestrate-engagement`
  gained a "Lifecycle, team, and termination" section.

## [1.0.85] — 2026-09-13

### Added — no-babysitting during scan + test

- MCP `instructions` gained a "NO-BABYSITTING (while scanning + testing)"
  section: scan the whole surface before reporting, test every hypothesis
  through its full cycle, persist through partial results, and only surface to
  the user for scope/consent/completion.
- `bs-orchestrate-engagement` carries the same rule, so a driving agent keeps
  scanning + testing autonomously instead of pausing to ask after each step.

## [1.0.84] — 2026-09-13

### Added — structured failure recovery (`retry_guidance`)

- New `retry_guidance` MCP tool + `intelligence/retry_guidance.json`: 7 failure
  modes (empty output, blocked, sanitized, subagent failed, model failed,
  unconfirmed, low severity) → concrete recovery actions, with alias resolution
  (`rate limit` → model_failed, `stale` → empty_output). Upgrades the
  "don't give up" doctrine from prose to a data-driven lookup.
- PERSISTENCE doctrine now leads with: on any failure, call
  `retry_guidance(signal)` for concrete recovery actions before giving up.

## [1.0.83] — 2026-09-13

### Removed — dead code, dead data, and stale docs (no decoration)

Full dead-code/dead-data audit. Removed:

- 16 `intelligence/*.json` files that were remnants of the removed deterministic
  engine and no longer loaded by any code (`ab_signals`, `attack_chains`,
  `awaiting_input_markers`, `endpoint_patterns`, `escalation_patterns`,
  `file_extensions`, `patterns`, `refusal_markers`, `scan_profiles`, `skills`,
  `tools`, `tools_meta`, `unified_patterns`, `verification_patterns`,
  `vuln_ontology`, `waff_bypass`) — superseded by `chains.json`, `skills/`,
  `tools-catalog.json`, and the live intel files.
- 3 `examples/*.sh` that invoked the removed `mission`/`benchmark` CLI.
- `templates/cves.json` (2.1 MB) — never loaded (NVD lookups use the API,
  CVE correlation uses `cve_correlations.json`).

Rewrote `docs/AUTONOMY.md` (was describing the removed deterministic engine)
to document the LLM-driven model, and updated `README.md` / `docs/usage.md` /
`THIRD-PARTY-NOTICES.md` to drop the removed `mission`/`benchmark` CLI,
`run_benchmark`, and the stale 12-sink-class / 106-check counts.

## [1.0.82] — 2026-09-13

### Added — attack-vector focus + chain-to-chain composition

- Attack vectors are now actionable: each of the 34 categories in
  `attack_vectors.json` gained a `focus` (what to test / look for), surfaced by
  `list_attack_vectors` and `attackVectors` — no longer bare names.
- New `chain_links` MCP tool + `intelligence/chain_links.json`: 18 chain→chain
  compositions (SSRF→metadata → default-creds→pivot via stolen IAM, XXE→SSRF →
  cloud metadata, SQLi→RCE → hash-dump, …) so a complex bug can be traced across
  chains instead of stopping at one.
- Doctrine: RESOURCE MAP now tells a driving LLM WHEN to reach for each —
  `list_attack_vectors` during recon, `list_chains` for escalation, `chain_links`
  to compose chains, `bypass_lookup` when blocked, `payload_lookup` for probes.

## [1.0.81] — 2026-09-13

### Added — bypass techniques + chain doctrine

- New `bypass_lookup` MCP tool + `intelligence/bypass_techniques.json`: concrete
  bypass techniques for WAF, input filter/sanitizer, auth (401/403), and
  rate-limit/captcha defenses (encoding, case, comment insertion, chunked,
  null byte, double-encoding, verb tampering, header spoofing, …) with examples,
  plus alias resolution (`403` → auth, `firewall` → waf).
- PERSISTENCE doctrine now tells a driving LLM to call `bypass_lookup` when a
  probe is blocked, and to chain findings (a low-severity hit usually escalates
  — match it to a multi-stage chain instead of stopping at the first vuln).

## [1.0.80] — 2026-09-13

### Added — full no-babysitting doctrine (resource map + persistence)

- MCP `instructions` gained a "RESOURCE MAP" section teaching a driving LLM the
  decision tree: TOOL acts, PLAYBOOK is the campaign plan for a target type,
  SKILL is phase/technique doctrine, MANUAL is one-tool reference, PAYLOAD is
  attack payloads, INTELLIGENCE is knowledge — and when to reach for each.
- Added a "PERSISTENCE" section: complex bugs do not give up — vary probes,
  re-run on empty output, challenge sanitizers, keep unconfirmed hypotheses,
  trace the full chain. Updated resource counts (17 playbooks, 317 manuals,
  66 payload collections).
- `bs-orchestrate-engagement` now tells the agent to read the matching playbook
  for the target type and carries the same persistence rule.

## [1.0.79] — 2026-09-13

### Fixed — scheme-less URL routing

- `classifyTarget` now recognizes URLs without a scheme: a bare domain, IP, or
  host:port (`example.com`, `192.168.1.1`, `example.com:8080`) is classified as
  live and gets `https://` auto-prepended; a bare code filename (`myfile.php`)
  is classified as source. `run_engagement` uses it, so a scheme-less URL routes
  to the live pipeline without the caller normalizing it.
- Routing doctrine (skill + MCP `instructions`) updated to state that a URL
  often carries no `http://`/`https://` prefix.

## [1.0.78] — 2026-09-13

### Added — automatic target routing (URL vs source)

- `bs-orchestrate-engagement` now leads with a "Target routing" table: a URL
  or bare hostname → live engagement (scope-gated); a filesystem path / code
  extension → source audit — classified automatically, no need to ask.
- MCP `instructions` gained a "0. ROUTE BY TARGET" step so a driving LLM
  auto-classifies the target and routes to the live or source pipeline without
  being told.

## [1.0.77] — 2026-09-13

### Fixed — explicit tool argument names in doctrine

- `bs-source-audit` now documents the exact argument convention: all
  source-analysis tools take `path` (file or directory); only `run_engagement`
  takes `target` (path or URL). Workflow steps now show `{path}` explicitly.
- `bs-orchestrate-engagement` tells sub-agents to load `source-audit` for the
  argument names instead of guessing `target` vs `path`.

## [1.0.76] — 2026-09-13

### Changed — native plan + sub-agent orchestration doctrine

- `bs-orchestrate-engagement` now instructs the driving agent to use its
  platform's native planning + delegation (e.g. Hermes `plan`/`todo` +
  `delegate_task`) to run the engagement in parallel — recon / analyze /
  deep-classes as sub-agents, then collect → verify → report — instead of
  serial tool calls.

## [1.0.75] — 2026-09-13

### Added — plan checklist in the engagement banner

- `run_engagement` now renders its engagement plan as a checkbox checklist
  (`[✓] done / [☐] pending`) right under the "orchestrator in control" banner,
  so the terminal shows both the takeover notice and what was/will be done.

## [1.0.74] — 2026-09-13

### Fixed — banner now visibly surfaces in the terminal

- `run_engagement` now returns the "orchestrator in control" banner as a
  standalone first text block (plus a one-line status summary), instead of
  burying it inside the JSON result — so it actually appears in the client
  terminal when the engagement starts.
- `bs-orchestrate-engagement` now instructs the driving agent to relay the
  banner verbatim and drive `blitz_status` for live progress.

## [1.0.73] — 2026-09-13

### Added — orchestrator "in control" banner + live progress

- `run_engagement` now returns a terminal-friendly banner announcing the
  engagement ("orchestrator in control") with the target, mode, and the
  canonical scope→recon→analyze→verify→review→report pipeline.
- New `blitz_status` MCP tool: format a live progress snapshot (current stage,
  checkmark/active/pending markers, finding counts, task status) so a driving
  agent can announce progress to the user as it works.

## [1.0.72] — 2026-09-13

### Changed — coordinated agent guidance

- Added `next_steps` directives for the three new sink classes (SSTI, XPath,
  LDAP injection) so a driving LLM is told exactly how to validate each one
  after detection — not just "go verify it".
- Updated the static MCP `instructions`: now directs the agent to `route_scan`
  and `complex_scan` for the deep/complex classes, and corrects the stale
  skill count (85 → 38).

## [1.0.71] — 2026-09-13

### Added — expanded sink-class coverage

- **Filled two empty sink classes** across all four languages:
  - `xml_processing` (XXE) — PHP `simplexml_load_string/file`, JS `DOMParser`,
    Python `etree.parse`/`minidom.parse`/`xml.sax`, Java XML parsers.
  - `archive_extraction` (zip slip) — PHP `->extractTo`, JS `extractAllTo`,
    Python `extractall`/`shutil.unpack_archive`, Java `ZipInputStream`.
- **Three new sink classes** (SSTI, XPath, LDAP injection) across PHP / JS /
  Python / Java adapters + the PHP depth layer.
- Fixed a coverage-matrix desync (Python `http_request` was marked false).
- Corpus grew 103 → 109 fixtures (tp=77, tn=32, fp=0, fn=0).

## [1.0.70] — 2026-09-13

### Fixed — polish from live LLM-driven verification

- `scope_check` now recognizes filesystem paths (static source) as always
  in-scope instead of refusing with a misleading empty-host message.
- `blitz_scan` (breadth) now matches Laravel static DB facade sinks
  (`DB::select`/`DB::raw`/`DB::statement`/`DB::insert`/`DB::update`/
  `DB::unprepared`, `->selectRaw`) — consistent with the depth layer.
- `generate_report` no longer renders `undefined` for findings that lack
  `status`/`confidence`/`id`; it defaults to `detected` / `unscored` / `(no id)`.

## [1.0.69] — 2026-09-13

### Changed — agent-native skills polish

- `bs-source-audit` now points the driving agent at the dedicated `route_scan`
  and `complex_scan` detectors for the deep/complex classes.
- `bs-orchestrate-engagement` gained a skill-chain map (which skill to load per
  phase) and a stale-server pitfall (reload MCP if a detector returns
  suspiciously empty output after an upgrade).

## [1.0.67] — 2026-09-13

### Changed — internal cleanup

- Removed stale internal references from source comments and docs so public
  artifacts are self-contained and generic.

## [1.0.66] — 2026-09-13

### Changed — LLM-driven architecture (Mission Control removed)

Aligned with the LLM-driven model: the LLM is the brain, Blitz Strike is the
deterministic hands. The deterministic "self-driving" engine is gone.

- **Removed** `src/mission/` (Mission Control loop, 13 deterministic agents,
  task scheduler, planner, coverage, recovery, router, budget, termination,
  mission CLI) and the `mission_start`/`status`/`resume`/`stop`/`list` MCP tools.
- **Added** `route_scan` + `complex_scan` MCP tools — the route-confusion and
  complex-bug detectors are now directly callable by a driving LLM agent.
- **Added** `run_enterprise_benchmark` MCP tool (framework-fixture recall).
- **Rewrote** `src/enterprise-benchmark.ts` to drive the detectors directly
  (no Mission Control) — 15/15 recall across the 6 fixtures.
- The 6 `bs-*` skills (step 2) teach the LLM how to drive these tools.

Deterministic moat intact: taint engine, universal taint, route-confusion,
complex-bugs, strike_verify, finding/evidence engine, browser agent, intel layer.

## [1.0.65] — 2026-09-13

### Fixed — breadth-scanner false positives (live MCP verification)

Found via an LLM-driven verification run (agent → `blitz_scan`/`eagle_eye2`):

- **Sink tokens in comments/strings no longer reported.** `scanFile`/
  `traceFunction`/`grepInFunctions` now match against a comment- and
  string-literal-stripped view of the source (positions + line numbers
  preserved). A `// use extract($_REQUEST)` comment or a
  `"https://…/system("` string is not a sink.
- Rebuilt `dist/` so the fix ships in the published bundle (a long-running MCP
  server must be restarted to pick up new `dist/` code — skills load fresh from
  `skills/`, but compiled engine code is loaded once at startup).

## [1.0.64] — 2026-09-13

### Added — agent-native skills (LLM-driven orchestration doctrine)

Six skills that teach the LLM agent how to drive Blitz Strike's deterministic
tools end-to-end (the "LLM is the brain, Blitz Strike is the hands" model):

- `bs-orchestrate-engagement` — the full cycle: scope → recon → analyze →
  verify → review → report, no-babysitting.
- `bs-scope-gate` — hard scope/authorization gate before any live action.
- `bs-source-audit` — drive taint + route-confusion + complex-bugs analyzers.
- `bs-verify-finding` — marker + negative-control live verification.
- `bs-adversarial-review` — the ten §15 questions + confidence + dedup.
- `bs-write-report` — submission-ready report (root cause, CVSS, remediation).

Plus `docs/ARCHITECTURE-AUDIT.md` — the Mission Control → LLM-driven toolbelt
classification (TOOL / SKILL / REDUNDANT).

## [1.0.63] — 2026-09-13

### Added — complex-bug detection (`src/complex-bugs.ts`)

Three "hard" vulnerability classes beyond source→sink taint:

- **Deserialization → POP gadget chain** — `unserialize()` of attacker-controlled
  data when a magic method (`__destruct`/`__wakeup`/`__toString`/`__invoke`/`__call`)
  is present in the file (object injection → RCE pivot).
- **Type juggling** — loose comparison (`==`/`!=`) of user input against a
  hash/secret (PHP `0e…` collision auth bypass); strict `===` is ignored.
- **Mass assignment** — `extract()` of request data without `EXTR_SKIP`, or
  `parse_str()` of user input (variable injection).

Wired into the `@source` agent as `vulnerability` graph nodes. Added a
`php-complex` fixture to the enterprise benchmark.

## [1.0.62] — 2026-09-13

### Added — route-confusion & dispatch-abuse detection

New vulnerability class distinct from source→sink taint (`src/route-confusion.ts`):
detects when the routing/dispatch layer lets an attacker reach an unintended
handler or control which handler runs.

- `dynamic_dispatch` — attacker-controlled callback/route (`call_user_func`,
  `forward`, `dispatch`, `resolve_route`, `invoke`).
- `dynamic_method_call` — `$obj->$method()` / `$class::$method()`.
- `dynamic_include` — `include`/`require` of a variable (LFI via route).
- `batch_forwarding` — a loop over sub-requests that forwards to inner handlers
  without a per-route authorization re-check.
- `route_normalization_gap` — route matching against user input without path
  normalization (strtolower/rtrim/urldecode).

Wired into the `@source` agent; findings become `route` nodes in the security
graph. Added a WordPress-style batch-endpoint fixture to the enterprise
benchmark (`wp-batch-route`).

## [1.0.60] — 2026-09-13

### Added — deeper taint-flow coverage

- **Method-call resolution** (`calleeName`) — `$obj->method()` now resolves to
  its method definition for interprocedural taint, not the object variable.
- **Built-in taint propagation** — `implode`/`join`/`sprintf`/`str_replace` and
  other array→string/format built-ins now carry taint through to the sink.
- **Cast handling** — `(array)`/`(string)` casts propagate taint (a string can
  still carry a payload); `(int)`/`(float)` casts act as an int_cast sanitizer.
- New corpus fixtures covering conditional-sanitizer bypass on array→SQL
  interpolation (`php-int-cast-bypass-vuln`/`-fixed`).

## [1.0.59] — 2026-09-13

### Added — enterprise-grade detection + benchmark

- **Enterprise benchmark** (`src/mission/enterprise-benchmark.ts`, `bench/enterprise/`):
  four realistic multi-file, framework-style fixtures (Laravel PHP, Express JS,
  Django Python, Spring Java) with ORM/query-builder abstractions and
  known-safe endpoints. `blitzstrike benchmark --enterprise` runs them; the
  engine now scores **10/10 vulns, 0 false positives**.

### Fixed — framework source/sink coverage (found by the enterprise benchmark)

- **PHP** — `sourceOf` now recognizes framework accessors (`$request->input()`,
  `->query()`, `->get()`, `->post()`, …) not just `$_GET`; `sinkClassOf` handles
  static calls (`DB::select()`, `DB::raw()`); and **function/method-internal
  sources** are now emitted (previously only top-level + tainted-argument flows
  were detected, so Laravel controllers scored 0).
- **JS** — removed `require()`/`child_process` module-import false positives;
  sink matching now keys on the callee (no nested-call double-count); and
  PostgreSQL `$1` parameterized queries are recognized as safe.
- **Python** — added Django/DRF sources (`request.GET`, `request.POST`,
  `request.data`, `request.query_params`).
- **Java** — added Spring/JAX-RS annotation sources (`@RequestParam`,
  `@PathVariable`, `@RequestBody`, …) and tightened sink variable extraction so
  the tainted variable is no longer pushed out of the window by SQL keywords.
- `@analysis` agent now imports the language adapters (multi-language detection
  previously returned 0 in the CLI/MCP path).

## [1.0.58] — 2026-09-13

### Fixed — total-verification pass

- **Backward-compat mission load** — `loadMission` now normalizes old persisted
  missions (missing the P14 budget fields: `max_tokens`, `max_cost_usd`,
  `per_task_budget`, `started_at`, `used_tokens`/`used_cost_usd`, and P9
  `failed_approaches`) so `blitzstrike mission resume <old-id>` no longer crashes.
- **Scope gate** — now rejects ANY non-local target without an authorized scope
  (previously the `https://` regex let a bare host like `example.com` slip past
  the upfront gate). Non-local + no scope → `scope_required`.
- README CLI section now lists the `mission` and `benchmark` commands.

## [1.0.57] — 2026-09-13

### Added — Autonomous Security Engine (phase 18: documentation & examples)

- `docs/AUTONOMY.md` — full reference for the autonomous engine (components,
  mission lifecycle, safety invariants, CLI, MCP mission mode, no-babysitting).
- `examples/` — runnable scripts: `mission-source.sh`, `mission-web.sh`,
  `benchmark.sh`.
- README — new "Autonomous engine" section + further-reading link.

## [1.0.56] — 2026-09-13

### Added — Autonomous Security Engine (phase 16: autonomous benchmark)

- **Autonomous Benchmark** (`src/mission/benchmark.ts`, §26):
  - `runAutonomousBenchmark()` — runs the FULL autonomous engine (Mission
    Control) against each labelled corpus fixture and reports tp/tn/fp/fn,
    precision, recall, F1, false-positive rate, time-to-completion, and budget.
  - New CLI command: `blitzstrike benchmark` (`--full` for the whole corpus).

### Fixed — multi-language source discovery

- `iterSourceFiles` (`TARGET_EXTS`) only indexed PHP extensions, so the
  autonomous engine silently skipped `.py`/`.java`/`.js`/`.ts` sources. Added
  the missing extensions — the autonomous benchmark now scores
  **precision 1.0 / recall 1.0 / F1 1.0** over the full 101-fixture corpus.

## [1.0.55] — 2026-09-13

### Added — Autonomous Security Engine (phase 15: termination engine)

- **Termination Engine** (`src/mission/termination.ts`, §24):
  - `evaluateTermination()` — ordered hard stops: user_interrupted →
    budget_exhausted → safety_violation → scope_violation → max_iterations →
    no_progress.
  - `objectiveComplete()` — all tasks in a terminal non-failed state.
  - `applyTermination()` — records the reason + detail into `decision_log` and
    sets `completed`/`terminated`.
  - `NO_PROGRESS_LIMIT` — iterations without progress before declaring stuck.
- Mission Control now terminates on ANY traceable reason (not just budget) and
  logs the termination decision with detail.

## [1.0.54] — 2026-09-13

### Added — Autonomous Security Engine (phase 14: budget controller)

- **Budget Controller** (`src/mission/budget.ts`, §22):
  - `budgetStatus()` — tracks time / tasks / requests / tokens / cost with
    per-dimension overrun flags.
  - `budgetOverrun()` — detects overruns and returns a specific reason
    (e.g. `budget overrun: tasks, requests`).
  - `consumeTasks()` / `consumeTokens()` — increment consumption counters.
  - `perTaskOverrun()` — enforces the per-task request budget.
- Extended the `Budget` type with `max_tokens`, `max_cost_usd`,
  `per_task_budget`, `started_at`, and `used_tokens`/`used_cost_usd`.
- Mission Control now terminates gracefully on ANY budget dimension overrun
  (not just tasks) and records a final budget snapshot in the decision log.

## [1.0.53] — 2026-09-13

### Added — Autonomous Security Engine (phase 13: model router)

- **Model Router** (`src/mission/router.ts`, §21):
  - Pure routing layer — never calls a model. Deterministic by default.
  - `routeTask()` — maps an agent type to a model tier (`large`/`medium`/`small`)
    only when a provider is configured; otherwise routes to `none`.
  - `AGENT_TIER` — §21 mapping (planning/source/review → large; attack execution
    → medium; verification → small).
  - `loadRouterConfig()` — reads `BLITZSTRIKE_MODEL_PROVIDER` / `_LARGE` /
    `_MEDIUM` / `_SMALL` env vars.
  - `routingPlan()` — full plan (all `none` when deterministic).
- Mission Control records the routing decision (tier) per task and the overall
  routing plan in the mission `decision_log`.

## [1.0.52] — 2026-09-13

### Added — Autonomous Security Engine (phase 12: browser automation agent)

- **Browser Automation Agent** (`src/browser-agent.ts`, §16):
  - Session-based (one persistent page) so multi-step flows work.
  - Ops: `open`/`navigate`/`click`/`type`/`evaluate`/`screenshot`/`back`/`forward`/
    `get_cookie`/`set_cookie`, plus `detectAuthForm()` and `browserDiagnostics()`.
  - Graceful degradation — every op reports `unavailable` when `playwright-core`
    (optional peer) is missing, never throws.
- New `@browser` mission agent (URL-scope-gated) — detects login forms and JS
  runtime errors and emits auth-flow hypotheses.
- New MCP tool `browser_agent` (session ops + detect_auth_form + diagnostics + close).

## [1.0.51] — 2026-09-13

### Added — Autonomous Security Engine (phase 11: adversarial reviewer)

- **Adversarial Reviewer** (`src/mission/reviewer.ts`, §15):
  - `reviewFinding()` — challenges a hypothesis with the ten §15 questions
    (reachability, auth required, authorization elsewhere, middleware, attacker
    control, sink reachability, caching, reproducibility, negative control,
    impact accuracy), each a deterministic check against evidence + Security Graph.
  - Returns CONFIRMED / REJECTED / NEEDS_MORE_EVIDENCE.
  - `reviewValidated()` — reviews every validated hypothesis in a mission.
- `@reviewer` now uses the full §15 review (rejects on any hard fail; demands
  more evidence when supporting signals are too weak).

## [1.0.50] — 2026-09-13

### Added — Autonomous Security Engine (phase 10: cross-agent memory)

- **Cross-agent Memory** (`src/mission/memory.ts`, §20):
  - `persistMissionMemory()` — persists confirmed findings (verified),
    rejected findings, and failed approaches (with `future_policy`) into the
    long-term memory store; pending hypotheses are NOT persisted (unverified).
  - `recallForTarget()` — retrieves memory relevant to a target, to seed a
    fresh mission.
- Mission Control's `finalize` now persists reusable knowledge and records the
  saved/deduped count in `memory_refs`.

## [1.0.49] — 2026-09-13

### Added — Autonomous Security Engine (phase 9: failure recovery)

- **Failure Recovery** (`src/mission/recovery.ts`, §17):
  - `diagnoseError()` — categorizes failures (network / permission /
    missing_tool / invalid_args / scope / unknown).
  - `recoveryDecision()` — network → retry (bounded); missing_tool → route to an
    alternative agent; scope / permission / invalid_args → record (no retry).
  - `AGENT_ALTERNATIVES` — fallback specialization per agent type.
  - `recordFailure()` — a failed-approach record with a `future_policy` so the
    autonomous system never blindly repeats the same mistake.
- Mission Control now routes task failures through the recovery engine and
  persists `failed_approaches` into the mission state.

## [1.0.48] — 2026-09-13

### Added — Autonomous Security Engine (phase 8: coverage-driven scheduler)

- **Coverage-driven Scheduler** (`src/mission/coverage.ts`, §13):
  - `computeCoverage()` — 10 dimensions (attack surface, endpoints, technologies,
    source files, sink classes, auth/authorization boundaries, vulnerability
    classes, attack vectors, escalation chains).
  - `coverageGaps()` — dimensions below a threshold.
  - `scheduleCoverageTasks()` — auto-generates tasks for under-covered
    dimensions, skipping already-attempted agents and mode-inappropriate ones
    (e.g. no `@web` for source audits; endpoints/technologies resolve locally).
  - `gapAgent()` — mode-aware dimension→agent mapping.
- Mission Control's `replan` now runs the coverage scheduler and persists
  per-dimension coverage into `mission.coverage.dimensions`.
- `@recon` now links discovered endpoints into the Security Graph (so coverage
  reflects real endpoint exploration).

## [1.0.47] — 2026-09-13

### Added — Autonomous Security Engine (phase 7: adaptive planner)

- **Adaptive Attack Planner** (`src/mission/planner.ts`, §11):
  - `ATTACK_BRANCHES` — data-driven technique library across SSRF / LFI / SQLi /
    RCE / XSS / IDOR / XXE / traversal (each with rationale, expected value,
    risk, evidence requirements, and tool).
  - `planNextActions()` — generates ranked next actions from unresolved
    hypotheses (confidence × expected-value − risk), evidence-driven branching.
  - `classifyType()` — maps hypothesis type strings to a technique class.
- **Escalation Graph** (`buildEscalationGraph`, §12) — integrates the 57
  escalation chains into the Security Graph (`vuln` → `enables` → `attack_chain`),
  seeded into every mission's world model.
- `@commander` now emits ranked `next_actions` from the adaptive planner.

## [1.0.46] — 2026-09-13

### Fixed (autonomous-engine milestone review)

- **Scope gate** — a URL mission without an authorized scope now terminates
  immediately with `scope_required` (no agent runs); `@recon` also refuses
  unscoped URL targets instead of falling through to a source scan.
- **Retry scheduling** — `retry` tasks are re-runnable again (treated as
  `pending`), so failed tasks retry then resolve to `failed` instead of sticking.
- **Security Graph now populated** — `@source` links sink nodes to the target;
  `@commander`/`@reviewer` read the graph (exposure + reachability) for strategy
  and adversarial review.
- **Hypothesis lifecycle wired** — `@validator` promotes/rejects hypotheses
  (validated/rejected) from STRIKE verdicts; `@reviewer` rejects low-confidence
  or unreachable findings.
- **Observability** — every agent decision is recorded in `decision_log`;
  the `@reporter` output is captured as the mission `report`.

## [1.0.45] — 2026-09-13

### Added — Autonomous Security Engine (foundation, phases 1–6 of 18)

The first milestone of the "Autonomous Security Research & Verification Engine"
upgrade — a Mission Control layer that wraps the existing BLITZ / EAGLE-EYE /
STRIKE core without replacing it.

- **Mission State** (`src/mission/state.ts`) — persistent, resumable missions
  (`~/.blitzstrike/missions/<id>.json`).
- **Task Graph** (`src/mission/taskgraph.ts`) — dependency-aware, parallel
  scheduling (pending/running/blocked/success/failed/retry/skipped/cancelled).
- **Security Graph** (`src/mission/graph.ts`) — shared world model (nodes +
  typed edges).
- **Hypothesis Engine** (`src/mission/hypothesis.ts`) — observation/hypothesis/
  validated/rejected with §14 confidence bands; never auto-confirms a hit.
- **Specialized Agents** (`src/agents.ts`) — 12 modular agents (@commander,
  @recon, @web, @api, @source, @auth, @mobile, @cloud, @analysis, @validator,
  @reviewer, @reporter), each wrapping an existing primitive.
- **Mission Control** (`src/mission/control.ts`) — the autonomous loop
  (observe → plan → act → collect → replan → terminate), stateful + resumable,
  mode profiles (web/api/source/mobile/cloud/bugbounty/redteam/audit).
- **CLI** — `blitzstrike mission <target> [--mode] [--scope]`, plus
  list/status/report/resume/stop subcommands.
- **MCP Autonomous Mission API** — `mission_start` / `mission_status` /
  `mission_resume` / `mission_stop` / `mission_list`.

## [1.0.44] — 2026-09-13

### Added

- **Autonomous no-babysitting orchestration** (the missing piece vs. a
  harness-level plugin loop):
  - `runEngagement` now returns the full deliverable **inline** — summary,
    markdown, JSON, and SARIF — so a single call completes a source audit
    (no separate `report` call needed).
  - `runLiveEngagement` — a fully autonomous live engagement for URL targets:
    scope gate → marker-reflection sweep (`strike_verify` per common parameter)
    → canonical findings via `resolveFinding` → inline report.
  - `run_engagement` MCP tool auto-branches: URL target → autonomous live
    sweep; source path → full static pipeline. Scope-gated and non-destructive
    (marker + negative control only).

## [1.0.43] — 2026-09-13

### Added

- **Phase 8 — Production Hardening**:
  - **Caching** (`src/cache.ts`, §46) — versioned result cache (`sha256(source) + engine_version`);
    wired into `analyzeDataFlow2` so unchanged files skip re-parsing.
  - **SARIF export** (`src/sarif.ts`, §32) — `toSarif()` emits a SARIF 2.1.0 document
    (GitHub Code Scanning / GitLab / Azure DevOps).
  - **Release validation** (`src/release.ts`, §49) — `validateRelease()` checks
    package.json vs CHANGELOG (hard) + git tag / npm registry / lockfile (soft).
  - **Dependency security** (`src/dependency.ts`, §50) — `checkDependencies()`
    inspects install-time scripts and git/unusual dependency sources.
  - **Incremental analysis** (`src/incremental.ts`, §47) — `analyzeChangedFiles()`
    re-analyzes only the files a commit touched (git diff → changed files → engine).
  - **CI/CD** (`.github/workflows/ci.yml`, §48) — typecheck, tests, build, npm pack,
    release-consistency, and dependency-surface gates.
  - `blitzstrike doctor` now reports release-metadata and dependency-surface health.

## [1.0.42] — 2026-09-13

### Added

- **Phase 7 — MCP Orchestration** (`src/orchestration.ts`, wired into `run_engagement`):
  - A data-driven **state machine** (10 states: scope_check → plan → recon →
    analyze → hypothesis → select_chain → validate → evidence → finding → report).
  - A deterministic **planner** (`buildPlan`) that emits an ordered plan with
    per-step tool, risk level, evidence requirements, and done/pending/blocked status.
  - A **risk policy** (`actionPermitted`) that gates high-risk actions
    (strike_verify, confirm_finding) behind scope.
  - **§34 agent guidance** (`computeGuidance`) — every result now exposes
    current_state / confidence / blocking_reason / required_evidence /
    recommended_next_action / recommended_tool.
  - `run_engagement` output now includes `state`, `plan`, `guidance`, and
    `risk_policy` (no new MCP tools added — the surface was deepened, not widened).

## [1.0.41] — 2026-09-13

### Added

- **Phase 6 — Browser Validation** (`src/browser.ts` + MCP tool `browser_validate`):
  - Playwright-based validation of static-analysis hypotheses (not a scanner —
    gated, "use only when necessary").
  - Checks: `dom_xss` (marker-payload execution), `open_redirect` (unexpected
    redirect), `auth_bypass` (missing auth enforcement), `csrf` (tokenless
    state-changing form).
  - Each check returns structured evidence (verdict + final_url + dom/console/
    page-error signals) suitable for attaching to a finding.
  - `playwright-core` is an **optional peer dependency**; `browser_validate`
    degrades to a clear `unavailable` result when it is not installed.
  - Hermetic browser test suite (`bun run test:browser`, 8 checks) against a
    local vulnerable server.

## [1.0.40] — 2026-09-13

### Changed (review + spec alignment)

- **Coverage Matrix 2.0 (§57)**: `coverageMatrix()` now also tracks the framework
  dimension — per-framework sinks/sources/sanitizers/auth counts + CWE set.
- **Benchmark 100+ (§65)**: corpus grown 70 → **101 fixtures** (70 vulnerable +
  31 patched), still scoring detection 1.0 / FP 0 / FN 0 / precision 1.0.

### Fixed

- JS adapter now detects `el.innerHTML = <tainted>` (property assignment) as a
  DOM XSS sink — previously only `innerHTML` inside call expressions was caught.

## [1.0.39] — 2026-09-13

### Added

- **Phase 5 — Framework Intelligence** (`src/frameworks.ts` + `intelligence/frameworks.json`):
  - Data-driven framework knowledge for 7 frameworks (361 patterns), extensible
    without code changes: Laravel, WordPress (PHP); Express, Next.js (JS/TS);
    Django, FastAPI (Python); Spring (Java). Rails (Ruby) deferred until Ruby support.
  - Each framework defines sources, sinks, sanitizers, auth gates, routing, ORM,
    and middleware patterns (with CWE tags on sinks).
  - `detectFramework(code, language)` — heuristic detection via scored signals.
  - `scanFramework(code, framework)` — framework-aware source/sink/sanitizer/auth hits.
  - New MCP tools: `list_frameworks`, `detect_framework`, `framework_intel`.

## [1.0.38] — 2026-09-13

### Fixed (Phase 4 review)

- `diff_analyze` ignored the `language` argument for non-PHP code (bare `file`
  without an extension resolved to `unknown`, silently returning 0 findings).
  The engine now derives a probe extension from the declared language.
- `eagle_eye2` now surfaces `entry_points` (uncalled functions = potential unauth
  entry points) and `unreachable` (dead code) — previously computed but hidden.
- Removed the unused `call_graph` field from `Eagle2Result.summary` (Map/Set-based,
  not JSON-safe, never consumed).
- Removed the dead `nextCorrelationId` export from `audit.ts`.

## [1.0.37] — 2026-09-13

### Added

- **Phase 4 — Differential security analysis** (`src/differential.ts`):
  - `analyzeDifferential(old, new, language)` — compares two code versions and
    surfaces only security-sensitive changes:
    - **new vulnerability** (source→sink path present only in new code — authoritative, engine-backed)
    - **fixed vulnerability** (path present only in old code)
    - **new sink** / **new source** (line-level hints)
    - **sanitizer removed** / **authorization removed** (high-severity signals)
  - `analyzeDifferentialFiles(old_path, new_path)` — file-based comparison.
  - `analyzeGitDiff(repo, base, head)` — runs across a git commit range.
  - New MCP tool `diff_analyze` (supports file-pair, code-pair, or git-diff mode).

## [1.0.36] — 2026-09-13

### Added

- **Phase 3 — Benchmark expansion** (`scripts/generate-corpus.py` + 70-fixture corpus):
  - Corpus grown 10 → **70 fixtures** (49 vulnerable + 21 patched/safe), covering
    11 sink types × 4 languages (PHP/JS/Python/Java) × vulnerable/patched pairs.
  - Benchmark now scores **detection 1.0 / FP 0 / FN 0 / precision 1.0**.
  - Benchmark PHP fixtures now run through **EAGLE-EYE 2.0** (`analyzeDataFlow2`),
    so return/byref/ternary/transitive cases are measured.

### Fixed (engine gaps exposed by the expanded corpus)

- **PHP**: `include`/`require`/`include_once`/`require_once` and `eval` are
  statement nodes (not calls) — now handled as sinks.
- **PHP**: `sinkClassOf` now prefixes `$` to property-lookup bases, so
  `$wpdb->get_var`/`$wpdb->get_results` are classified correctly.
- **PHP**: method chains (`DB::table()->whereRaw()->get()`) — nested sinks are
  now detected by recursing into the chain base.
- **PHP**: `in_array`/`preg_match`/`ctype_*`/`is_numeric` whitelist guards are
  recognized as input-validation gates (sinks inside them are suppressed).
- **PHP**: `wp_safe_redirect` is the *safe* redirect (removed from the redirect sink).
- **Universal adapters**: added SSRF sinks (JS `http.get`/`axios`, Python
  `requests.*`, Java `new URL`/`openConnection`), path-traversal (JS
  `fs.readFile`), and XXE (Java `DocumentBuilder`/`SAXParser`).
- **Universal adapters**: parameterized SQL (`?` placeholder + params) and
  Python `subprocess` list-form (no shell) are now recognized as safe.

## [1.0.35] — 2026-09-13

### Added

- **Phase 2 — EAGLE-EYE 2.0** (`src/callgraph.ts` + `src/eagle2.ts`):
  - **Call graph** — sound (over-approximate) function/method resolution on a
    PHP AST: name calls, `$this->m()`, static calls, and Class Hierarchy
    Analysis (CHA) for `$obj->m()`.
  - **Whole-program interprocedural taint** — call-graph worklist propagates
    taint transitively across function boundaries (`outer -> inner -> sink`).
  - **Return propagation** — `$x = helper($tainted)` taints `$x` iff the helper
    returns a value derived from its parameter.
  - **By-reference alias tracking** — `&$out` output params that write a source
    taint the caller's variable.
  - **Conditional flow** — ternary (`retif`) + if/else branches are merged
    (sources unioned, sanitizers intersected — sound).
  - **Authorization flow** — sinks guarded by a capability/nonce check are
    flagged `auth_gated` with the *specific* gate name.
  - New MCP tool `eagle_eye2` — prefer over `taint_scan` for accurate
    cross-function reachability.

### Fixed

- Sink classification false positives: bare function-name sinks (`system(`, `exec(`, …)
  now use `\b` word boundaries, so `outer_exec(...)` is no longer misclassified
  as command execution.

## [1.0.34] — 2026-09-13

### Fixed (Phase 1 review)

- `hasSecrets` rewritten as `redactSecrets(text) !== text` — deterministic
  (fixed the `g`-flag `.test()` state bug) and no false positive on already-redacted
  content (`password=[REDACTED]` is no longer flagged).
- Wired `finding_updated` audit event into `transition()` / `rejectFinding()`.

## [1.0.33] — 2026-09-13

### Added

- **Phase 1 — Core Integrity** (per the master upgrade spec):
  - **Finding invariants** (`src/invariants.ts`) — hard, machine-checkable rules:
    a finding cannot be CONFIRMED without evidence, cannot be CONFIRMED with a
    failed negative control, cannot be CONFIRMED out of scope, cannot persist a
    raw secret, and its evidence hash must stay stable. Enforced in
    `confirmFinding` and re-checkable via `checkFindingInvariants`.
  - **Evidence provenance** (`src/evidence.ts` §16) — every evidence record now
    carries chain-of-custody metadata (`tool`, `version`, `target`, `scope`,
    `parentEvidence`).
  - **Audit log** (`src/audit.ts` §45) — structured append-only audit events
    (`scope_checked`, `finding_created`, `finding_updated`, `validation_finished`,
    `evidence_created`, …) at `~/.blitzstrike/audit.jsonl`, wired into scope
    check, finding creation, evidence attachment, and validation.
  - `confirmFinding` now **throws** if called with no evidence (hard invariant).

### Changed

- `scopeCheck` refactored to a single exit path that always records a
  `scope_checked` audit event.
- Shared `src/version.ts` — single source of truth for the package version
  (removed the duplicate VERSION readers in `server.ts`).

## [1.0.32] — 2026-09-13

### Added

- Self-update: `blitzstrike update` CLI command + `check_update` MCP tool
  (`src/update.ts` with semver-aware version comparison).

## [1.0.31] — 2026-09-13

### Changed

- npm publish pipeline debug (version bump only, no functional change).

## [1.0.30] — 2026-09-13

### Changed

- Removed source attribution from the attack-vector taxonomy data (first-party
  content; `_comment` and notices stripped).

## [1.0.29] — 2026-09-13

### Added

- Attack-vector taxonomy (`intelligence/attack_vectors.json`, 34 categories /
  588 vectors) + `list_attack_vectors` + `attack_vectors` MCP tools.

## [1.0.28] — 2026-09-13

### Fixed

- Benchmark corpus writes to the OS temp directory (hermetic; no writes inside
  the read-only package).

## [1.0.27] — 2026-09-13

### Added

- Documentation milestone: CHANGELOG / ROADMAP / README + docs metrics.

## [1.0.26] — 2026-09-13

The first hardening milestone: the whole roadmap is implemented, measured, and
type-safe. "A scan hit is a hypothesis; a live test is the verdict" is now a
code path, not a slogan.

### Added

- **STRIKE validation engine** (`src/strike.ts`) — baseline + marker +
  negative-control requests produce a deterministic verdict (`confirmed` /
  `false_positive` / `unconfirmed` / `blocked`), wired into the finding
  lifecycle via `resolveFinding` (`hypothesis → validating → confirmed`).
- **`strike_verify`** rewritten and **`strike_resolve`** added — attach a live
  verdict to a finding, advancing its lifecycle + attaching SHA-256 evidence.
- **CVSS v3.1 calculator** (`src/cvss.ts`) + `cvss_score` tool — self-computed
  base score, vector, and severity (verified against known NVD values), not
  read from NVD.
- **Finding deduplication** (`src/dedup.ts`) + `dedup_findings` tool — collapse
  findings that share a root cause (sink × source × CWE) across engagements.
- **Reproducible report generator** (`src/report.ts`) + `generate_report` tool —
  deterministic markdown/JSON report with summary + SHA-256 integrity hash.
- **Benchmark framework** (`src/benchmark.ts` + `bench/corpus/`) + `run_benchmark`
  tool — labelled vulnerable/safe corpus across 4 languages measuring detection
  rate, false-positive rate, and precision.
- **Coverage matrix** (`src/coverage.ts`) + `coverage_matrix` tool — enumerates
  language × sink-class coverage (4 languages × 12 sink classes).
- **Dynamic guidance** (`src/guidance.ts`) — every trace/scan/verify result
  returns `next_steps` directives so a driving agent knows the next move.
- **Modular live reconnaissance** (`src/live-recon.ts`) + `live_recon` tool —
  fingerprint, WAF/tech/version detection, crawler, parameter discovery,
  subdomain enumeration, Wayback CDX, API discovery, port scan, intel correlation.
- **Universal multi-language taint** (`src/universal-taint.ts` + `src/adapters.ts`)
  — PHP (php-parser), JavaScript/TS (@babel/parser), Python (@lezer/python),
  Java (java-parser), all pure-JS (no tree-sitter native addons).
- **3 memory/confidence tools** — `memory_forget`, `confidence_weights`,
  `finding_attach_evidence` (wired previously-dead exports into the surface).
- **CI workflow** (`.github/workflows/ci.yml`) — typecheck + build + regression
  suite on every push and pull request.
- **47 missing tool manuals** generated (`scripts/generate-manuals.py`) —
  manual coverage went 270 → 317 indexed manuals (334 files), 100% of the
  130-tool catalog is now documented.
- **Attack-vector taxonomy** (`intelligence/attack_vectors.json` +
  `list_attack_vectors` + `attack_vectors` tools) — a 34-category / 588-vector
  master reference of web attack vectors (RCE, SQL, auth, SSRF, XSS, API,
  business logic, race conditions, cloud, supply chain, CI/CD, AI/LLM, Web3,
  XS-leaks, …) for BLITZ attack-surface mapping.
- **Self-update** (`blitzstrike update` + `check_update` tool) — query the npm
  registry for the latest version (semver-aware) and refresh the heavy data
  cache (payloads + templates) in one shot.

### Changed

- **MCP surface grew 33 → 54 tools.**
- `bun run test` now runs the formal regression + benchmark suite
  (106 checks), replacing the ad-hoc `test/verify.ts` invocation.

### Fixed

- **Node crash (latent)** — `require("node:fs")` inside ESM modules
  (`memory.ts`, `benchmark.ts`) worked under Bun but threw `require is not
  defined` under plain Node (the `npx` path). Replaced with top-level imports.
- **`trace_data_flow` next_steps broken** — `taintedSinks` collected SinkClass
  *objects* instead of string sink ids, so sink-specific guidance never matched.
  Now collects `sink.id`.
- **`strike_verify` ignored its `timeout` parameter** — now threaded into the
  request.
- **Dead code eliminated** — 12 unused locals/params/imports + 4 dead exports +
  1 dead re-export, all removed or wired into tools.

### Hardening

- **Type safety** — 59 scattered `any` usages reduced to 0 literals. Internal
  JSON/data types got explicit interfaces (`WafDetection`, `TechCorrelationResult`,
  `EnrichResult`, `ScopeResult`, `NvdResponse`, `FofaResponse`, …). The only
  remaining `any` is a single documented `AstNode` alias marking the external
  untyped-parser boundary (php-parser / babel / lezer / java-parser).

## [1.0.0] — 2026-09-12

### Added

- **33 MCP tools** across 6 tiers: BLITZ (triage), EAGLE-EYE (trace), STRIKE
  (verify + orchestrate), CATALOG (tools + skills), MANUALS (deep reference),
  INTELLIGENCE (WAF/correlations/fuzzer), MEMORY (self-growing knowledge).
- **3-tier methodology** — `run_engagement` runs scope gate → triage → chain
  enrichment → findings server-side, in a single call from any MCP client.
- **57 escalation chains** (`chains.json`) with `invariant_check` +
  `negative_control` per step (surface-pattern false-positive elimination).
- **130-tool catalog** (`tools-catalog.json`) — 15 categories covering bug
  bounty, reverse engineering, blue/red team, forensics, mobile, AD, cloud.
- **270 deep tool manuals** + 17 engagement playbooks (kali-pentest, Apache-2.0).
- **32 universal skill playbooks** — adversary-playbook + hack.proof (MIT).
- **Intelligence data layer** — WAF signatures (139), tech/CVE/port correlations,
  fuzzer data, exploit payloads (66 categories), nuclei templates (11.9k).
- **Memory layer** — append-only JSONL knowledge store with dedup; auto-captures
  matched chains on engagement, grows with every run.
- **CLI** — `serve`, `doctor` (health check with severity + fix), `install`
  (auto-detect + merge MCP config into Claude/Cursor/OpenCode), `version`.
- **Distribution** — ESM bundle + single static binary (`bun build --compile`).

### Changed

- Moved from Python prototype to TypeScript/Bun for zero-install `bunx`/`npx`
  distribution and first-class `@modelcontextprotocol/sdk` support.

### Removed

- Personal attack-tree playbooks (private methodology, not universal scripts).
