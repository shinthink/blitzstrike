---
name: container-image-scan
description: Use when you need to check a Docker/OCI image or Dockerfile for vulnerable base images, known-CVE packages baked into layers, exposed secrets in build layers, and bad Dockerfile practices (running as root, secrets in ARG/ENV, unpinned base tags).
---

# Container image scan

## Prerequisites

- `trivy`, `grype`, `hadolint`

## Workflow

1. **Scan the built image for OS + package vulnerabilities:**
   ```bash
   trivy image --severity HIGH,CRITICAL -o findings/trivy-image.json --format json your-image:tag
   ```
   Cross-check with grype (different vuln DB, catches different things):
   ```bash
   grype your-image:tag -o json > findings/grype.json
   ```

2. **Scan for secrets baked into layers** — a secret in an intermediate build layer is still extractable even if the final `Dockerfile` deletes it:
   ```bash
   trivy image --scanners secret your-image:tag
   ```

3. **Lint the Dockerfile itself:**
   ```bash
   hadolint Dockerfile
   ```
   Manually confirm these regardless of what the linter catches:
   - Base image uses a pinned digest or specific version tag, not `:latest`
   - No `ADD` from a remote URL without checksum verification (prefer `COPY` + explicit download+verify steps)
   - Final stage doesn't run as `root` — there's a `USER` directive to a non-root user
   - Multi-stage build used to keep build-time secrets/toolchain out of the final image
   - No secrets passed via `ARG`/`ENV` (these persist in image history/metadata even if unset later — use build secrets (`--mount=type=secret`) instead)
   - `.dockerignore` excludes `.git`, `.env`, and other sensitive local files from the build context

4. **Filesystem/config scan** if scanning source rather than a built image (also catches IaC misconfig in the same pass — overlaps with `iac-cloud-posture`):
   ```bash
   trivy fs --severity HIGH,CRITICAL .
   ```

## Output

`findings/trivy-image.json`, `findings/grype.json`, hadolint output. Report per finding: package/layer, CVE, severity, fix (usually "bump base image to X" or "pin and rebuild").

## Notes

- Rebuilding with an updated base image is the fix for the large majority of image-scan findings — check whether a newer base tag already resolves most of the list before triaging CVEs one by one.
- If findings persist against packages you don't directly control (transitive OS packages in the base image), check whether a `.trivyignore` suppression is justified (no fix available, not reachable) vs. just noise-hiding a real issue — document the reasoning either way.
