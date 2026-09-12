---
name: ci-cd-pipeline-security
description: Use when you need to check CI/CD pipeline configuration for supply-chain risk — poisoned pipeline execution, secret exposure to untrusted code, overly broad permissions on pipeline tokens, and unpinned third-party actions/steps. Distinct from secrets-scan (which checks for leaked secrets already committed) — this checks whether the pipeline itself is designed to leak or misuse them.
---

# CI/CD pipeline security

## Prerequisites

- `zizmor` (GitHub Actions-specific), manual review for other CI systems (GitLab CI, CircleCI, Jenkins)

## Workflow

1. **Automated lint pass** (GitHub Actions):
   ```bash
   zizmor . -o findings/zizmor.json
   ```

2. **Manually confirm these regardless of CI platform:**
   - **Untrusted input reaching a shell** — workflows triggered by `pull_request_target` or similar that interpolate PR title/body/branch-name directly into a shell step (`run: echo "${{ github.event.pull_request.title }}"`) let a PR author inject arbitrary commands into a privileged context. This is the single most common real-world CI supply-chain bug.
   - **Secrets exposed to fork PRs** — confirm secrets aren't available to workflows triggered by `pull_request` from forks (they shouldn't be, by GitHub's default, but check for `pull_request_target` misuse that reintroduces this) or equivalent "run untrusted code with trusted credentials" patterns on other CI platforms.
   - **Unpinned third-party actions/steps** — third-party GitHub Actions referenced by mutable tag (`uses: some/action@v1`) instead of a pinned commit SHA can change underneath you if the upstream repo is compromised. Recommend pinning to a full SHA for anything not first-party/`actions/*`.
   - **Overly broad token permissions** — default `GITHUB_TOKEN` permissions should be scoped down (`permissions: contents: read` at minimum, elevated only on the specific jobs that need write access) rather than left at the default broad grant.
   - **Self-hosted runner exposure** — if self-hosted runners process PRs from public forks, a malicious PR can achieve arbitrary code execution on infrastructure with network access to internal systems. Public repos should use GitHub-hosted runners for anything triggered by external contributions, or gate self-hosted runner jobs behind maintainer approval.
   - **Deploy credentials scope** — CD steps should use short-lived, narrowly-scoped credentials (OIDC federation to cloud providers rather than long-lived static keys stored as secrets) where the platform supports it.

3. **Check the artifact/release pipeline specifically** — confirm build artifacts are signed/attested (SLSA provenance, cosign) where the project publishes anything consumed by others (npm package, Docker image, binary release), so a compromised build step can't silently ship a tampered artifact.

## Output

`findings/zizmor.json` plus manual notes. Report per finding: workflow file, the specific pattern, why it's exploitable (walk the actual attack path — "a PR from any external contributor can inject a shell command here because X"), fix.

## Notes

- This skill and `secrets-scan` should both run as part of onboarding any new repo, and ideally as a recurring CI job on the pipeline configs themselves, not just a one-time check.
