---
name: iac-cloud-posture
description: Use when you need to check Terraform/CloudFormation/Kubernetes manifests for misconfiguration before deploy, or check a live AWS/Azure/GCP account's actual posture after deploy — public S3 buckets, overly permissive IAM, open security groups, unencrypted storage, missing logging.
---

# IaC & cloud posture

Two passes: static (before deploy, on the IaC source) and live (after deploy, on the actual account). Do both — drift between what the Terraform says and what's actually deployed is common and is itself a finding.

## Prerequisites

- `checkov`, `tfsec` (static IaC)
- `prowler` or `scoutsuite` (live cloud account), `kube-bench` (live K8s cluster)
- Read-only cloud credentials scoped to the account being assessed

## Workflow

### Static — before or independent of deploy

1. **Scan Terraform/CloudFormation/K8s manifests:**
   ```bash
   checkov -d . --output json --output-file-path findings/checkov.json
   tfsec . --format json > findings/tfsec.json
   ```

2. **Prioritize by blast radius, not raw count** — checkov/tfsec both produce large result sets. Triage in this order:
   - Public exposure: S3/storage buckets, databases, or search indices reachable without auth
   - IAM: wildcard (`*`) resource or action permissions, especially on roles assumable by a service with external input (Lambda behind a public API, CI runners)
   - Encryption: unencrypted storage/EBS/RDS, missing encryption-in-transit
   - Network: security groups/NSGs open to `0.0.0.0/0` on anything other than 80/443
   - Logging/monitoring: CloudTrail/audit logging disabled — this doesn't cause a breach but blinds you to one

### Live — against the deployed account

3. **Run a live account assessment:**
   ```bash
   prowler aws --output-formats json-asff -M json -o findings/
   ```
   or for multi-cloud:
   ```bash
   scoutsuite aws --report-dir findings/scoutsuite
   ```

4. **Diff live findings against static findings.** Anything live-only means either the Terraform doesn't reflect reality (manual console changes, drift) or the resource wasn't provisioned via IaC at all — both are process findings worth flagging even beyond the specific misconfig.

5. **Kubernetes, if applicable** — run from a node or pod with cluster access:
   ```bash
   kube-bench run --targets master,node,etcd,policies -j > findings/kube-bench.json
   ```
   Manually confirm: no workloads running as root without justification, network policies exist and default-deny where appropriate, secrets aren't mounted as plain env vars where a mounted volume would do, RBAC roles aren't cluster-admin by default.

## Output

`findings/checkov.json`, `findings/tfsec.json`, live scanner output, `findings/kube-bench.json` where applicable. Report grouped by blast radius (public exposure first), each with the specific resource, the misconfiguration, and the exact IaC change or console fix.

## Notes

- Read-only credentials are sufficient for every step here — never use write-capable credentials for an assessment pass.
- A single public storage bucket with real data in it is a critical finding regardless of how clean everything else is — don't let it get buried in a long checkov output list.
