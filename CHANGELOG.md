# Changelog

All notable changes to Blitz Strike are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
