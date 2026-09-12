# Prowler

- **Category**: Cloud-Native / Cloud Configuration Audit
- **Risk Level**: 🟡 Medium

---

## Description

Cloud security assessment and compliance tool, strongest for AWS and also supporting Azure, GCP, Kubernetes, and Microsoft 365. Use it for CIS, compliance, IAM, S3, network exposure, logging, and encryption checks.

## Installation

```bash
pipx install prowler
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `aws` / `azure` / `gcp` / `kubernetes` | Provider |
| `--profile <name>` | AWS profile |
| `--region <region>` | Limit region |
| `--output-formats <formats>` | Output formats such as `csv`, `json-ocsf`, `json-asff`, and `html` |
| `--output-directory <dir>` | Output directory |
| `--checks <ids>` | Run selected checks |
| `--compliance <name>` | Compliance framework |
| `--services <svc1> [<svc2> ...]` | Filter checks by AWS service (e.g., `iam`, `s3`, `ec2`) |

## Common Commands

```bash
# AWS JSON-OCSF audit
prowler aws --profile <profile> --output-formats json-ocsf --output-directory /tmp/prowler

# Run selected AWS checks
prowler aws --checks s3_bucket_public_access iam_user_mfa_enabled --output-formats json-ocsf

# Kubernetes audit
prowler kubernetes --output-formats json-ocsf --output-directory /tmp/prowler-k8s
```

## Notes & Tips

1. Prowler can generate many findings; group by service, severity, and account before reporting.
2. Use least-privilege read-only credentials when possible.
3. Cloud scans may enumerate sensitive metadata; store outputs as confidential evidence.

---

## Official References

- [Prowler Documentation](https://docs.prowler.com/)
- [Prowler GitHub](https://github.com/prowler-cloud/prowler)
