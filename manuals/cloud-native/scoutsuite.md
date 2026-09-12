# ScoutSuite

- **Category**: Cloud-Native / Cloud Configuration Audit
- **Risk Level**: 🟡 Medium

---

## Description

Multi-cloud security auditing tool for AWS, Azure, GCP, Alibaba Cloud, and Oracle Cloud. It enumerates cloud configuration and produces local reports with prioritized security findings.

## Installation

```bash
pipx install scoutsuite
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `aws` / `azure` / `gcp` | Cloud provider module |
| `--profile <name>` | AWS CLI profile |
| `--regions <list>` | Limit AWS regions |
| `--report-dir <dir>` | Output directory |
| `--no-browser` | Do not open browser automatically |
| `--services <list>` | Restrict services |

## Common Commands

```bash
# AWS audit using an existing profile
scout aws --profile <profile> --report-dir /tmp/scoutsuite --no-browser

# Azure audit
scout azure --report-dir /tmp/scoutsuite --no-browser

# GCP audit
scout gcp --report-dir /tmp/scoutsuite --no-browser
```

## Notes & Tips

1. Cloud credentials and subscriptions/accounts must be explicitly authorized.
2. ScoutSuite is read-only when used with audit permissions; still treat discovered resource names and policies as sensitive.
3. Use Prowler for deeper AWS compliance checks when AWS is the main target.

---

## Official References

- [ScoutSuite GitHub](https://github.com/nccgroup/ScoutSuite)

