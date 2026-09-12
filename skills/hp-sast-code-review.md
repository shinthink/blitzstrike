---
name: sast-code-review
description: Use when you need to find vulnerabilities in source code itself — injection sinks, unsafe deserialization, hardcoded crypto, path traversal, command injection, unsafe eval/exec, missing auth checks — without running the app. Complements dependency-audit (which checks other people's code) by checking yours.
---

# Static code review (SAST)

Pattern and data-flow analysis across the codebase. Fast, no running target needed, good signal on injection-class bugs.

## Prerequisites

- `semgrep` (primary — multi-language, huge community + OWASP ruleset)
- Language-specific fallback for deeper analysis: `bandit` (Python), `gosec` (Go), `CodeQL` (deepest, GitHub-native, slower to set up)

## Workflow

1. **Broad pass with semgrep's security rulesets** — start here regardless of language:
   ```bash
   semgrep scan --config "p/owasp-top-ten" --config "p/security-audit" --config "p/secrets" --json -o findings/semgrep.json .
   ```

2. **Language-specific deep pass** where applicable:
   ```bash
   # Python
   bandit -r . -f json -o findings/bandit.json
   # Go
   gosec -fmt json -out findings/gosec.json ./...
   ```

3. **Manually walk high-signal sink categories** semgrep may under-flag depending on ruleset coverage — search for these patterns directly and trace whether user input reaches them:
   - Raw SQL string concatenation/formatting (`f"SELECT * FROM {table}"`, template-literal SQL) instead of parameterized queries
   - `eval`, `exec`, `Function()`, `pickle.loads`, `yaml.load` (not `safe_load`), unsafe deserialization
   - Shell-out calls built from user input (`os.system`, `subprocess` with `shell=True`, `child_process.exec`) instead of argument arrays
   - Path construction from user input without normalization/allowlisting (`../../etc/passwd` traversal)
   - Hardcoded cryptographic keys, IVs, or use of broken primitives (MD5/SHA1 for passwords, ECB mode)
   - Auth/authorization checks that exist on one code path but are missing on an equivalent one (e.g., REST endpoint checks a role, the corresponding GraphQL resolver doesn't)

4. **Triage for exploitability, not just pattern match.** Semgrep and bandit both produce real false positives (sanitized input reaching a "dangerous" sink, test-only code, intentionally trusted internal calls). For each high/critical finding, trace the actual data flow from source to sink before reporting it as real — this is the single most valuable thing an agent adds over a bare tool run.

## Output

`findings/semgrep.json` plus any language-specific report. Report format per finding: file:line, rule/CWE, one-line description of the actual vulnerable flow (not just the rule name), and a concrete fix (parameterize this query, replace `eval` with `json.loads`, etc.).

## Notes

- Run this against the diff, not just the full repo, when auditing a PR — `semgrep scan --config ... --baseline-commit <base-sha>` scopes to changed lines only and is dramatically faster for CI use (see `ci-cd-pipeline-security`).
- Zero findings doesn't mean the code is clean — SAST is pattern-matching. Pair with `business-logic-fuzzing` for logic flaws that have no unsafe-pattern signature at all.
