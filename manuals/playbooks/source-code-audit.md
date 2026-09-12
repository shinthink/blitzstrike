# Source Code & Dependency Audit Playbook

Use for authorized source code repositories, build artifacts, CI/CD pipelines, or dependency manifests where SAST, secret scanning, and software composition analysis are in scope.

## Inputs

- Repository paths, archive files, or remote Git URLs in scope.
- Language stack, build system, and package manifest files (e.g., `requirements.txt`, `package.json`, `pom.xml`, `go.mod`).
- Whether Git history is in scope for secret scanning.
- Approved output formats and data-handling rules for credential findings.

## Workflow

1. **Scope and access validation**
   - Confirm what is in scope: working directory, full Git history, CI artifacts, dependency lock files, or container images built from the code.
   - Record repository name, commit hash or tag, and language/framework before scanning.

2. **Secret and credential scanning**
   - Scan directories and Git history for hardcoded secrets, API keys, tokens, and credentials.
   - Use `gitleaks git` when Git history is in scope; use `gitleaks dir` for unpacked archives or non-Git directories.
   - Treat all findings as sensitive evidence; redact secrets before sharing reports.

   (See `../web/README.md` for `gitleaks` and related tool selection.)

   ```bash
   # Scan Git history
   gitleaks git --redact -f json -r /tmp/gitleaks_git.json /path/to/repo
   # Scan directory without Git history
   gitleaks dir --redact -f json -r /tmp/gitleaks_dir.json /path/to/source
   # Suppress already-known findings with a baseline
   gitleaks git --baseline-path /tmp/baseline.json --redact -f json -r /tmp/gitleaks_new.json /path/to/repo
   ```

   See `../web/tools/gitleaks.md` for full parameter reference.

   **Zero-secrets verification:** If gitleaks reports zero findings, run a manual spot-check before accepting the result — `grep -rn` for patterns like `AKIA`, `BEGIN RSA`, `BEGIN OPENSSH`, `password\s*=`, `api_key\s*=` across source files. Document the manual check.

3. **SAST — static application security testing**
   - Run a language-appropriate SAST tool against the source tree to identify injection sinks, unsafe deserialization, weak crypto, path traversal, and other code-level vulnerabilities.
   - Preferred tools by language:
     - **Multi-language**: `semgrep` with community or custom rulesets (`semgrep --config auto <path>`)
     - **Python**: `bandit -r <path> -f json -o /tmp/bandit.json` + `semgrep`
     - **JavaScript/TypeScript**: `semgrep` + `njsscan -o /tmp/njsscan.json --json <path>`
     - **Go**: `semgrep` + `gosec -fmt=json -out=/tmp/gosec.json ./...`
     - **Java**: `semgrep` + `find-sec-bugs` concepts (integrate via build plugin or standalone analysis)
     - **Ruby**: `brakeman -o /tmp/brakeman.json -f json`
     - **C/C++**: `flawfinder --json <path> > /tmp/flawfinder.json`
     - **All**: `trivy fs --scanners misconfig,secret <path>` for config and secret checks alongside dependency scanning
   - Decision point: detect languages present in the repository (inspect file extensions, build files) and select the appropriate SAST tool chain before scanning.
   - Validate SAST findings manually before reporting; tools produce false positives at scale.

   **Finding validation methodology:** Do not report raw SAST output as findings. For each high/critical finding: (1) trace data flow from user input (source) to the dangerous function (sink), (2) check whether sanitization or framework-level protection exists along the path, (3) determine if the code path is reachable from an external entry point. Mark each as: confirmed, likely, false positive, or requires live testing.

   See `../vulnerability/tools/trivy.md` for `trivy fs` usage.

   3b. **Manual code review**
   - Search for dangerous function patterns that commonly lead to vulnerabilities:
     - Command injection: `eval()`, `exec()`, `system()`, `Runtime.exec()`, `os.popen()`, `subprocess.call()` with `shell=True`
     - Deserialization: `deserialize()`, `pickle.loads()`, `yaml.load()` (without `SafeLoader`), `ObjectInputStream`, `unserialize()`
     - Client-side injection: `innerHTML`, `dangerouslySetInnerHTML`, `document.write()`, `v-html`
     - SQL injection: raw query construction with string concatenation or f-strings
   - Trace user input from entry points (controllers, routes, API handlers) to sinks (database queries, file operations, command execution, template rendering). Map the data flow to confirm exploitability.
   - Review authentication and authorization logic: are all endpoints protected? Can authorization checks be bypassed through parameter manipulation, forced browsing, or IDOR? Check for missing authentication on admin or internal endpoints.
   - Review error handling: are exceptions caught and handled securely? Is sensitive data (stack traces, database errors, internal paths) leaked in error messages or API responses?
   - Use `grep`/`semgrep` with custom rules for project-specific patterns:

   ```bash
   # Search for dangerous function patterns
   grep -rn "eval\|exec\|system\|pickle\.loads\|yaml\.load\|innerHTML\|dangerouslySetInnerHTML" <path> --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.rb"
   # Semgrep with custom rules
   semgrep --config /tmp/custom-rules.yaml <path> -o /tmp/semgrep_custom.json --json
   ```

4. **Software composition analysis (SCA) and dependency vulnerabilities**
   - Identify known CVEs in third-party dependencies by scanning manifest files or lock files.
   - Use `trivy fs --scanners vuln` for broad language support; use `grype` as an alternative when an SBOM is available.
   - For specific ecosystems: `pip-audit` for Python, `npm audit` for Node.js.

   **Dependency reachability assessment:** Do not report all CVEs as equal findings. For high/critical CVEs, check whether the vulnerable function/module is actually imported and used by the application code. Prioritize CVEs where the vulnerable code path is reachable over those present in the dependency tree but never invoked.

   ```bash
   # Scan a source tree for dependency vulnerabilities (supports most ecosystems)
   trivy fs --scanners vuln --format json -o /tmp/trivy_deps.json /path/to/repo
   # Generate an SBOM then scan it
   syft /path/to/repo -o cyclonedx-json > /tmp/sbom.json
   grype sbom:/tmp/sbom.json -o json > /tmp/grype.json
   # Python dependencies
   pip-audit -r requirements.txt -o /tmp/pip_audit.json -f json
   # Node.js dependencies
   npm audit --json > /tmp/npm_audit.json
   ```

5. **IaC and configuration review**
   - Scan Dockerfile, Kubernetes manifests, Terraform, Helm charts, and CI/CD pipeline files for misconfigurations.
   - Use `trivy config` for IaC files; note findings alongside dependency and SAST results.
   - Check CI/CD pipeline configuration files for security issues:
     - `.github/workflows/` (GitHub Actions): hardcoded secrets in env vars or step inputs, overly permissive `permissions` (e.g., `contents: write` when not needed), use of `pull_request_target` with checkout of PR code, unpinned third-party actions.
     - `.gitlab-ci.yml` (GitLab CI): exposed variables, shared runners with sensitive access, artifact security.
     - `Jenkinsfile` (Jenkins): hardcoded credentials, insecure `sh` steps, overly broad agent labels.
   - Look for secrets in pipeline configs: API keys, tokens, passwords passed as plain-text environment variables rather than through a secrets manager.
   - Assess artifact security: are build artifacts (packages, images, binaries) signed? Can the pipeline be manipulated to produce tampered artifacts?

   ```bash
   trivy config --severity HIGH,CRITICAL --format json -o /tmp/trivy_iac.json /path/to/repo
   # Search for hardcoded secrets in CI/CD files
   grep -rn "password\|secret\|token\|api_key\|AWS_ACCESS" .github/workflows/ .gitlab-ci.yml Jenkinsfile 2>/dev/null
   ```

   See `../vulnerability/tools/trivy.md` for IaC scan modes.

6. **Triage and deduplication**
   - Correlate secret, SAST, and SCA findings; eliminate duplicates across tools.
   - Prioritize: confirmed valid secrets > exploitable code paths > HIGH/CRITICAL CVEs in reachable dependencies > informational misconfigurations.
   - Record the tool, rule/CVE ID, file path, line number, and reproduction steps for each confirmed finding.

## Cross-References

- `web-application.md` — live web endpoint testing.
- `api-security.md` — live API endpoint testing.
- `reporting-workflow.md` — findings documentation.

## Expected Artifacts

- Secret scan report with source (history vs. working tree), file path, and match type; secrets redacted.
- SAST findings by tool, rule, file, and line with severity.
- Dependency vulnerability report with CVE IDs, affected packages, versions, and fix availability.
- SBOM in CycloneDX or SPDX format if generated.
- IaC misconfiguration findings with resource and check ID.

## Stop When

- All in-scope repositories, manifests, and artifact paths have been scanned.
- SAST findings have been validated with data-flow tracing, not reported as raw tool output.
- Zero-secret scanner results have been manually verified.
- High/critical dependency CVEs have been assessed for reachability.
- Further work requires accessing production secrets, running code under test, or testing live endpoints (switch to `web-application.md` or `api-security.md`).
