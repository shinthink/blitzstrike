# Contributing to Blitz Strike

Thanks for considering contributing. Blitz Strike is a universal MCP
security-audit toolbelt — contributions to data layers, chains, tools catalog,
manuals, and the core engine are all welcome.

## Before you start

- **Read the methodology.** Every finding is a hypothesis until a live test
  proves it. Contributions that add surface-level patterns without a refutation
  step (`negative_control`) will be asked to add one.
- **License compatibility.** Blitz Strike is MIT. Vendored third-party data must
  be MIT or Apache-2.0 (never SUL-1.0 or other non-permissive licenses). Add
  every vendored source to `ATTRIBUTION.md` with its license + copyright.
- **No credentials.** Never commit API keys, tokens, or `.env` files.

## Project layout

```
src/            TypeScript engine (scanner, orchestrator, catalog, intel, ...)
chains.json     57 escalation chains (data-driven)
tools-catalog.json  130-tool catalog
skills/         32 third-party playbooks (ap-*, hp-*)
manuals/        270 deep tool manuals + 17 playbooks
intelligence/   21 JSON data files (WAF, correlations, fuzzer)
payloads/       66 exploit-payload categories
templates/      ~11.9k nuclei YAML detection templates
test/verify.ts  43-check assertion suite
```

## Adding an escalation chain

Edit `chains.json`. Each chain needs:

```json
{
  "id": "chain_id_snake_case",
  "name": "Human readable name",
  "triggers": ["sink", "patterns"],
  "required_findings": ["what must already be observed"],
  "severity": "critical|high|medium|low",
  "steps": [
    {
      "order": 1,
      "action": "what to do",
      "tool_hint": "which tool",
      "success_criteria": "binary observable",
      "invariant_check": "assumption that MUST hold",
      "negative_control": "how to refute the finding"
    }
  ],
  "tools": ["recommended", "external", "tools"]
}
```

A chain without `negative_control` is a false-positive generator, not a chain.

## Adding a tool to the catalog

Add an entry to `tools-catalog.json`:

```json
{
  "name": "toolname",
  "category": "recon|enumeration|exploitation|blue-team|...",
  "description": "...",
  "command": "base command",
  "flags": [{"flag": "-h", "description": "..."}],
  "install": {"linux": "...", "darwin": "...", "win32": "..."},
  "check_installed": {"command": "tool -h", "exit_code": 0}
}
```

The `check_installed` command must exit non-127 when the tool exists (127 =
"not found" is the only reliable missing signal).

## Development

```bash
bun install          # deps
bun run typecheck    # tsc --noEmit
bun run build        # ESM bundle → dist/index.js
bun run test/verify.ts   # 43-check assertion suite
```

Run the full suite before opening a PR. All checks must pass.

## Commit style

Single, clean commits. No credentials, no build artifacts, no `node_modules`.
