# Roadmap

Blitz Strike is version 1.0. This is where it's headed.

## Done

- [x] **npm publish** — `npx blitzstrike` zero-install for every MCP client.
- [x] **Phase 1 — Finding engine** — canonical Finding schema, evidence +
      SHA-256 integrity, secret redaction, confidence scoring, strict lifecycle.
- [x] **Phase 2 — Source-to-sink tracing** — universal multi-language taint
      (PHP/JS/TS/Python/Java), sanitizer + auth-gate awareness, variant grouping.
- [x] **Phase 3 — STRIKE validation** — baseline + marker + negative control →
      deterministic verdict, wired into the finding lifecycle.
- [x] **Phase 4 — Benchmark & regression** — labelled corpus (detection rate /
      false-positive rate / precision), coverage matrix, CI, formal test suite.
- [x] **Type hardening** — 59 scattered `any` → 0 literals; explicit interfaces
      for all internal JSON/data shapes.

## Near term

- [ ] **Client-side pentest** — Playwright browser automation for DOM XSS,
      auth-flow replay, and CSRF PoC generation (verifiable, not decorative).
- [ ] **XML + archive sink coverage** — `xml_processing` and `archive_extraction`
      are the two sink classes still uncovered (see `coverage_matrix`).
- [ ] **Java/Go/Ruby taint precision** — Java adapter is currently regex-oriented;
      Go and Ruby are not yet covered by the universal engine.

## Medium term

- [ ] **Exploit script library** — universal exploit scripts (single + mass-scan
      pattern) wired into `run_engagement`, replacing the "playbook only" model.
- [ ] **Wizard installer** — interactive `install` (platform → client → verify)
      with a health-check report, matching the on-rails UX of the best MCP tools.
- [ ] **HTTP transport** — optional remote MCP endpoint for shared/team servers.

## Long term

- [ ] **Multi-agent orchestration** — parallel specialist agents per tier
      (recon / trace / verify) coordinated by `run_engagement`.
- [ ] **Verification corpus** — a growing set of confirmed findings feeding the
      memory layer, so every engagement makes the toolbelt smarter.

## Principles

- Data over bloat. Breadth is JSON/markdown; methodology is the differentiator.
- Everything wired, nothing decorative. A feature that isn't exercised in the
  flow is removed.
- License-safe. MIT/Apache-2.0 only for vendored data.

## Release pipeline

Publishing is automated via npm **trusted publishing (OIDC)** — see
`.github/workflows/release.yml`. No npm token or 2FA is required; push to `main`
with a bumped `package.json` version and the workflow publishes directly with
SLSA provenance.
