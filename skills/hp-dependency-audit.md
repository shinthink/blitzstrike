---
name: dependency-audit
description: Use when you need to know which third-party packages/libraries in a project have known CVEs, and whether a fix version exists. Covers npm/yarn/pnpm, pip/poetry, Go modules, Cargo, and Ruby Gemfiles via OSV plus ecosystem-native tools.
---

# Dependency audit (SCA)

Software composition analysis: find known-vulnerable versions of things you depend on but didn't write.

## Prerequisites

- `osv-scanner` (cross-ecosystem, works from lockfiles directly — start here regardless of stack)
- Ecosystem-native fallback: `npm audit` (Node), `pip-audit` (Python), `cargo audit` (Rust), `bundler-audit` (Ruby)
- `syft` for SBOM generation if the user wants a bill of materials alongside the vuln list

## Workflow

1. **Universal first pass** — osv-scanner reads whatever lockfiles it finds (`package-lock.json`, `poetry.lock`, `go.sum`, `Cargo.lock`, etc.) in one pass:
   ```bash
   osv-scanner scan source -r . --format json > findings/osv.json
   ```

2. **Ecosystem-native cross-check** (catches advisories osv.dev hasn't ingested yet, or ecosystem-specific issues):
   ```bash
   # Node
   npm audit --json > findings/npm-audit.json
   # Python
   pip-audit -f json -o findings/pip-audit.json
   # Rust
   cargo audit --json > findings/cargo-audit.json
   ```

3. **Generate an SBOM** for the report and for future diffing:
   ```bash
   syft dir:. -o cyclonedx-json > findings/sbom.json
   ```

4. **Triage by reachability, not just presence.** A CVE in a transitive dependency you never call is lower priority than one in a package whose vulnerable function is actually in your call path. If the finding count is large, prioritize:
   - Direct dependencies over transitive
   - `critical`/`high` CVSS with a known public exploit
   - Packages with an available fix version (report the exact bump needed)

5. **Check for a fix, not just a CVE ID.** For each high/critical finding, confirm whether upgrading resolves it and whether that upgrade is a major-version bump (breaking-change risk) or a patch (safe to auto-apply). Recommend `npm audit fix`, `pip install -U <pkg>`, or the equivalent — but flag major bumps for the user to review rather than applying blind.

## Output

`findings/osv.json`, `findings/sbom.json`, plus whichever ecosystem-native report ran. Report format: package name, current version, fix version, CVE/GHSA ID, severity, direct-or-transitive.

## Notes

- Lockfile-less projects (no `package-lock.json`, floating `requirements.txt` without pins) can't be scanned reliably — flag "no lockfile" itself as a finding, since it also means non-reproducible builds.
- Don't stop at "X vulnerabilities found" — a raw count from `npm audit` is close to meaningless without severity and reachability context. Always translate to "here are the 3 that matter and why."
