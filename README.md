<div align="center">

<a href="https://github.com/shinthink/blitzstrike"><img src="./.github/assets/banner.webp" alt="Blitz Strike" width="100%" /></a>

[![GitHub Release](https://img.shields.io/github/v/release/shinthink/blitzstrike?color=369eff&labelColor=black&logo=github&style=flat-square)](https://github.com/shinthink/blitzstrike/releases)
[![GitHub Stars](https://img.shields.io/github/stars/shinthink/blitzstrike?color=ffcb47&labelColor=black&style=flat-square)](https://github.com/shinthink/blitzstrike/stargazers)
[![License](https://img.shields.io/badge/license-MIT-97CA00?labelColor=black&style=flat-square)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?labelColor=black&logo=typescript&logoColor=white&style=flat-square)](https://www.typescriptlang.org/)
[![Bun](https://img.shields.io/badge/Bun-1.4+-000000?labelColor=black&logo=bun&logoColor=white&style=flat-square)](https://bun.sh)
[![MCP](https://img.shields.io/badge/MCP-SDK-6366f1?labelColor=black&style=flat-square)](https://modelcontextprotocol.io)

</div>

# Blitz Strike

**Reconnaissance at speed. Analysis in depth. Validation before report.**

Blitz Strike is a structured penetration-testing methodology — reconnaissance,
source analysis, and validation — delivered as a universal MCP server. It
enumerates the attack surface (BLITZ), traces source-to-sink reachability
(EAGLE-EYE), and verifies each finding live before it is reported (STRIKE).
One server, every agent: scope enforcement to submission-ready findings in a
single `run_engagement` call, with the relevant exploit-tool manual attached to
every result.

> A scan hit is a **hypothesis**. A live test is the **verdict**.
>
> Blitz Strike exists to eliminate the two most common failure modes in
> automated security assessment: false positives from surface-level pattern
> matching, and unverified findings reported without live confirmation.

---

## What it does

Blitz Strike is a Model Context Protocol (MCP) server (TypeScript / Bun) that
packages a 3-tier security-audit methodology as callable tools — and runs the
whole engagement **server-side**, so a single `run_engagement` call works from
Claude Code, Cursor, Hermes, OpenCode, Claude Desktop, Gemini, or any MCP client.

### The three tiers

Blitz Strike maps a structured penetration-testing methodology — reconnaissance,
source analysis, and validation — into three tool tiers executed server-side.

| Tier | Name | Phase | What it does |
|---|---|---|---|
| 1 | **BLITZ** | Reconnaissance & attack-surface mapping | Enumerates the exposed attack surface at scale: unauthenticated entry points, dangerous sinks, and authentication boundaries. |
| 2 | **EAGLE-EYE** | Static analysis & data-flow tracing | Traces source-to-sink reachability and enriches findings against the escalation-chain graph. Confirms a sink is *reachable*, *unauthenticated*, and *exploitable* — not merely present. |
| 3 | **STRIKE** | Validation & exploitation | Performs live verification (marker reflection + negative control), scope enforcement, and orchestration so a finding is confirmed before it is ever reported. |

Reconnaissance → analysis → validation. Nothing is reported until STRIKE
confirms it.

---

## Autonomous, LLM-driven

Blitz Strike is driven by the LLM — Claude, Hermes, OpenCode, Codex, or any
MCP client. **The LLM is the brain** (plans, routes, delegates, judges); **Blitz
Strike is the deterministic hands + knowledge + guardrails**.

A full engagement is one call, or a granular agent-orchestrated cycle:

```bash
npx blitzstrike serve --mcp   # connect your agent, then ask it to
                              #   "audit ./src" (source) or "audit https://example.com" (live)
```

The LLM classifies the target automatically (URL → live pipeline, filesystem
path → source pipeline), then drives recon → analyze → verify → review →
report — guided by the bundled doctrine (`instructions` + skills + per-step
`next_steps`) and fanned out across the platform's native sub-agents.

→ [Autonomy & doctrine](docs/AUTONOMY.md) — how the LLM is steered.

## Why TypeScript / Bun

- **Single static binary** via `bun build --compile` — ship one executable per platform.
- **Zero-install distribution** via `bunx blitzstrike` / `npx blitzstrike`.
- **MCP TypeScript SDK** first-class (`@modelcontextprotocol/sdk`).
- **One toolchain** for dev + test + build + compile.

---

## Quickstart (30 seconds)

```bash
# Zero-install — works from any MCP client, no clone, no build
npx -y blitzstrike doctor        # verify the environment
npx -y blitzstrike install       # auto-register with every detected agent CLI
```

`npx blitzstrike install` detects every installed agent CLI (Claude Code,
Cursor, OpenCode, Codex, Hermes, Gemini, Windsurf, Copilot, Cline) and writes
the correct MCP config to each one in its native format. Restart your agent and
call `run_engagement`.

From source:

```bash
git clone https://github.com/shinthink/blitzstrike.git
cd blitzstrike
bun install
bun run src/index.ts serve --mcp
```

---

## Client Configuration (works in any MCP client)

```json
{
  "mcpServers": {
    "blitzstrike": {
      "command": "blitzstrike",
      "args": ["serve", "--mcp"]
    }
  }
}
```

- **Claude Code / Desktop**: `claude_desktop_config.json` or `.mcp.json`
- **Cursor**: `.cursor/mcp.json`
- **OpenCode**: `.mcp.json`
- **Hermes**: `mcp_servers:` in `config.yaml`
- **Gemini / Copilot**: native MCP config

Run `blitzstrike install` to print the exact snippet.

---

## CLI

```bash
blitzstrike serve --mcp       # start MCP server over stdio (default)
blitzstrike doctor            # health check: runtime + 130-tool catalog + creds
blitzstrike install           # write MCP config to detected clients (Claude/Cursor/OpenCode)
blitzstrike install --dry-run # preview the config without writing
blitzstrike sync-data         # fetch heavy datasets (payloads + templates) on-demand
blitzstrike update            # check for a newer version + refresh the data cache
blitzstrike version           # print version
```

### What doctor checks

| Check | Status you'll see |
|---|---|
| Runtime (bun/node) | OK / FAIL + fix |
| Security tools catalog | 63/130 installed, 67 on-demand |
| FOFA credentials | OK / WARN + fix |
| Data layers (chains + tools-catalog) | present / missing |

Each issue carries a `fix:` line — no guessing.

### What install does

`blitzstrike install` detects which MCP client config files already exist
(Claude `~/.claude.json`, Cursor `~/.cursor/mcp.json`, project `.mcp.json`) and
**merges** the Blitz Strike server entry in — it never overwrites your existing
MCP servers. With no client detected, it prints the snippet for manual paste.

---

## Tools

### BLITZ — attack-surface triage

| Tool | Purpose |
|---|---|
| `blitz_scan(path, max_files)` | Scan a source tree: enumerate unauth entry points + dangerous sinks with file:line refs. |
| `blitz_file(path)` | Same scan, single file. |

### EAGLE-EYE — deep trace

| Tool | Purpose |
|---|---|
| `eagle_eye(path, symbol)` | Return a function's full body, sinks in scope, and auth gates in scope. |
| `eagle_grep(path, sink, max_hits)` | Precision sink grep — report a hit ONLY inside a function body, flagged guarded/un-guarded. |
| `enrich_scan(path, max_files)` | Scan + match detected sinks to escalation chains (chains.json). |

### STRIKE — verify + recon + orchestrate

| Tool | Purpose |
|---|---|
| `strike_verify(url, method, data, headers, marker, timeout)` | Live HTTP verification with marker + negative control + baseline. |
| `strike_resolve(finding, verdict)` | Attach a live STRIKE verdict to a finding and advance its lifecycle. |
| `scope_check(target, scope, mode)` | Enforce scope before active testing (no-DoS, exclusion-aware, mode-gated). |
| `run_engagement(target, scope, mode, max_files)` | Full 3-tier audit in ONE call — scope gate → triage → chain enrichment → findings. |
| `list_chains()` | List all escalation chains in the data layer. |
| `fofa_search(query, size, fields)` | FOFA asset index search (needs `FOFA_EMAIL` + `FOFA_KEY`). |
| `nvd_lookup(cve_id)` | CVE lookup from NVD 2.0 (no key required). |
| `live_recon(url)` | Modular passive-first recon: fingerprint, WAF/tech/version, crawler, params, subdomains, Wayback, API discovery, port scan. |

### CATALOG — breadth layer (tools + skills knowledge base)

| Tool | Purpose |
|---|---|
| `tool_lookup(name)` | Look up a tool's command + flags + install + check. |
| `list_tools()` | List all catalog tools, grouped by category. |
| `skill_lookup(topic)` | Search the skills/ playbook knowledge base by topic. |
| `list_skills()` | List all skill playbooks. |
| `read_skill(name)` | Read the full content of a playbook. |
| `ensure_tool(name)` | Check if a tool is installed; if not, auto-install it. |

### MANUALS — deep tool reference + playbooks (wired into flow)

| Tool | Purpose |
|---|---|
| `read_tool_manual(name)` | Read a full deep manual for a tool (317+ manuals). |
| `list_manuals()` | List all manuals + playbooks. |
| `read_playbook(name)` | Read an engagement playbook (web-app, api-security, AD, etc.). |
| `list_playbooks()` | List all 17 engagement playbooks. |

### PHASE 4 — verification, measurement, reporting

| Tool | Purpose |
|---|---|
| `cvss_score(AV, AC, PR, UI, S, C, I, A)` | Compute a deterministic CVSS v3.1 base score + vector + severity (self-computed, not read from NVD). |
| `dedup_findings(findings)` | Collapse findings that share a root cause (sink × source × CWE) into one group per root cause. |
| `generate_report(findings, format)` | Emit a reproducible markdown/JSON report with summary + SHA-256 integrity hash. |
| `run_enterprise_benchmark()` | Run the labelled enterprise corpus and report detection rate, false-positive rate, and precision. |
| `coverage_matrix()` | Enumerate language × sink-class coverage (4 languages × 15 sink classes) + coverage ratio. |

### EAGLE-EYE — taint + data-flow

| Tool | Purpose |
|---|---|
| `taint_file(path)` | Inter-procedural taint analysis (PHP) — reachable, sanitized, authorized sinks. |
| `taint_scan(code, language)` | Universal taint analysis (PHP/JS/TS/Python/Java) with source→sink tracing. |
| `taint_tree(path)` | Taint propagation tree — how a source flows to a sink. |
| `trace_data_flow(path)` | Window-based data-flow trace with sanitizer + auth-gate awareness. |
| `variant_analysis(path)` | Group reachable sinks into variant families. |
| `list_languages()` | List supported analysis languages + extensions. |

### INTELLIGENCE — data layer (WAF + correlations + fuzzer)

| Tool | Purpose |
|---|---|
| `detect_waf(headers, body)` | Detect a WAF from response headers/body (139 signatures). |
| `tech_correlation(tech)` | Correlate tech to known vulns + CVEs (89 technologies). |
| `cve_correlation(cve)` | Correlate CVE to product + targets + severity (53 CVEs). |
| `port_correlation(port)` | Correlate port to service + attack vectors (103 ports). |
| `fuzzer_payloads(category)` | Fuzzing payloads + vulnerable patterns + chain rules. |
| `intel_summary()` | Counts of every intelligence dataset. |
| `payload_lookup(topic)` | Find exploit payloads (66 categories from PayloadsAllTheThings). |
| `read_payload(category)` | Read a full payload collection. |
| `template_lookup(topic)` | Find nuclei detection templates (11.9k YAML signatures). |
| `list_attack_vectors()` | List the full web attack-vector taxonomy (34 categories, 588 vectors). |
| `attack_vectors(category)` | Enumerate the vector list for one category (e.g. ssrf, business logic, ai/llm). |
| `check_update()` | Query the npm registry for the latest blitzstrike version. |

The intelligence layer (WAF signatures, tech/CVE/port correlations, fuzzer
data, vuln ontology, exploit payloads, nuclei detection templates) is sourced
from airecon (MIT), PayloadsAllTheThings (MIT), and nuclei-templates (MIT) —
loaded at runtime and wired into the tool surface above. The attack-vector
taxonomy (`intelligence/attack_vectors.json`) is first-party.

317 indexed tool manuals + 17 playbooks from kali-pentest (Apache-2.0) — 334
manual files, 100% of the 130-tool catalog documented. These are NOT
decoration — they are wired into the flow:

- `tool_lookup(name)` auto-attaches the tool's full manual.
- `run_engagement()` attaches the relevant manual per matched chain's `tools` field.

### MEMORY — long-term knowledge (self-growing)

| Tool | Purpose |
|---|---|
| `remember(topic, content, type, tags, verified)` | Save a reusable insight (deduped). verified=true only if marker reflected + negative control inert. |
| `memory_lookup(query)` | Search memory by topic/tag/content, scored. |
| `memory_list()` | List all memory entries, grouped by type. |
| `memory_forget(id)` | Remove a memory entry (append-only tombstone). |
| `confidence_weights(...)` | Get or set the confidence-scoring weight factors. |
| `finding_attach_evidence(finding, type, description, content)` | Attach a redacted + hashed evidence record to a finding. |

Memory is append-only JSONL at `~/.blitzstrike/memory.jsonl` (override with
`BLITZSTRIKE_HOME`). `run_engagement` auto-captures matched escalation chains
as `pattern` entries (deduped by chain id), so the knowledge base grows with
every engagement — no duplicate spam, and only `verified=true` entries are
authoritative.

---

## Tools Catalog (tools-catalog.json)

130 self-written security tools (not copied from any project), each with command
base, key flags, install command per platform, check_installed probe, phase,
tags, alternatives, requires_root, pipes, and homepage.

| Category | Count | Examples |
|---|---|---|
| recon | 23 | subfinder, amass, httpx, naabu, katana, trufflehog |
| exploitation | 13 | sqlmap, commix, dalfox, hydra, hashcat, phpggc |
| blue-team (defensive) | 13 | suricata, zeek, osquery, wazuh, sigma, yara, trivy |
| reverse-engineering | 12 | ghidra, radare2, gdb, pwndbg, angr, binwalk |
| enumeration | 11 | nuclei, ffuf, gobuster, arjun, wafw00f |
| forensics | 10 | volatility3, autopsy, tshark, foremost, steghide |
| active-directory | 8 | netexec, impacket, bloodhound, certipy, kerbrute |
| mobile | 7 | frida, objection, mobsf, apktool, jadx |
| post-exploitation | 6 | linpeas, pspy, chisel, ligolo-ng, pwncat |
| red-team | 6 | sliver, havoc, metasploit, evilginx3, gophish |
| utility | 6 | curl, jq, anew, notify |
| web | 4 | wpscan, joomscan, droopescan, cmseek |
| wireless | 4 | aircrack-ng, wifite, bettercap |
| cloud | 4 | pacu, prowler, scoutsuite, cloudfox |
| crypto | 3 | hashid, ciphey, rsactftool |

## Skills Knowledge Base (skills/)

32 skill playbooks (markdown) — universal, license-safe hidden gems from the
internet (MIT). Our personal attack-tree playbooks were removed (they were
private methodology, not universal exploit scripts).

- **adversary-playbook (14, MIT)** — `ap-*` prefix. Rare offensive playbooks:
  cross-forest-trust-abuse, gitea-ci-injection, kerberos-trust-abuse,
  multi-domain-ad-attacks, client-side-crypto-forgery.
- **hack.proof (18, MIT)** — `hp-*` prefix. End-to-end audit playbooks:
  full-security-audit, smart-contract-audit, api-security-test, sast-code-review,
  container-image-scan, iac-cloud-posture.

See `ATTRIBUTION.md` for full license/copyright notices.

---

## Escalation Chains (chains.json)

57 data-driven escalation chains, each with ordered steps carrying:

- `tool_hint` — which Blitz Strike tool to use
- `success_criteria` — binary observable for the step
- `invariant_check` — the assumption that MUST hold for exploitation
- `negative_control` — how to refute the finding

Examples: `ssrf_cloud_metadata`, `lfi_log_poison_rce`, `appkey_leak_deserialization_rce`,
`hmac_empty_key_forgery`, `intval_form_id_bypass`, `extract_variable_injection_lfi`,
`split_controller_upload_bypass`, `race_condition_double_spend`, `ssti_template_injection_rce`,
`jwt_alg_confusion_forgery`, `cache_poisoning_xss`, `subdomain_takeover`, and more.

Edit `chains.json` to add knowledge — never hardcode in source.

---

## Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `FOFA_EMAIL` | For `fofa_search` | FOFA account email |
| `FOFA_KEY` | For `fofa_search` | FOFA API key |
| `H1_USERNAME` | Optional | Your HackerOne username. When set, every outbound security-testing request carries `X-HackerOne-Research: <username>` so targets/triagers can identify you (responsible-disclosure convention). |
| `BLITZSTRIKE_HOME` | Optional | Override the home directory (default `~/.blitzstrike`). |
| `BLITZSTRIKE_DATA` | Optional | Override the data-cache directory (default `~/.blitzstrike/data`). |

All other tools need no credentials.

---

## Build

```bash
bun install          # deps
bun run typecheck    # tsc --noEmit
bun run build        # ESM bundle → dist/index.js
bun run test         # regression + benchmark suite (183 checks)
bun run compile      # single static binary → dist/blitzstrike
```

---

## Quality (measured, not claimed)

Blitz Strike carries a benchmark suite and a coverage matrix so quality is a
number you can re-run, not a claim.

- **Benchmark** (`run_enterprise_benchmark`) — a labelled corpus of vulnerable +
  safe fixtures across PHP, JavaScript, Python, and Java. Current result:
  detection rate **1.0**, false-positive rate **0**, precision **1.0**.
- **Coverage matrix** (`coverage_matrix`) — 4 languages × 15 sink classes =
  56/60 pairs covered. The four uncovered pairs are legitimately absent from
  the language (e.g. Java has no `eval`, Python/Java no PHP-style file
  inclusion, JS no deserialization sink).
- **Attack-vector taxonomy** (`list_attack_vectors` / `attack_vectors`) — a
  master reference of 34 attack-vector categories (588 vectors) so a driving
  agent can map the *entire* attack surface, not just the obvious sinks.
- **Regression suite** — `bun run test` runs 183 checks covering finding
  lifecycle, evidence integrity, CVSS math, taint tracing, dedup, report
  integrity, and benchmark invariants. CI runs it on every push.

---

## Methodology Notes

- **Sink ≠ vuln.** A dangerous function in the same *file* as an unauth handler does not mean the handler calls it. Use `eagle_eye` to confirm scope.
- **File write ≠ RCE (CF-003).** A writable file must be *loaded by the runtime* to be execution.
- **Default server config only.** Default Apache `FilesMatch .+\.ph(ar|p|tml)$` has a `$` anchor — `.php.jpg` does not execute.
- **Every finding is a HYPOTHESIS** until `strike_verify` reflects your marker AND the chain's `negative_control` stays inert.

---

## Disclaimer

This tool is provided for educational and authorized security research only.
Do not use against systems without explicit permission from the owner.

---

## Further Reading

- [Installation](docs/installation.md) — prerequisites, install, client registration.
- [Usage](docs/usage.md) — one-call engagement, granular path, modes, memory.
- [Autonomy & doctrine](docs/AUTONOMY.md) — LLM-driven autonomy, resource map, guardrails.
- [Manifesto](docs/manifesto.md) — the invariants that drive the methodology.
- [Contributing](CONTRIBUTING.md) — how to add chains, tools, and data.
- [Changelog](CHANGELOG.md) — version history.
- [Roadmap](ROADMAP.md) — where this is headed.
- [Security](SECURITY.md) — responsible disclosure + authorized use.
- [Third-Party Notices](THIRD-PARTY-NOTICES.md) — vendored data licenses.
