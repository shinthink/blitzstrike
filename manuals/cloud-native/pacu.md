# Pacu

- **Category**: Cloud-Native / AWS Exploitation
- **Risk Level**: 🔴 High

---

## Description

AWS exploitation framework by Rhino Security Labs. Interactive CLI tool with modules for IAM enumeration, privilege escalation, service exploitation, persistence, and data exfiltration across AWS services (EC2, S3, IAM, Lambda, RDS, etc.). Stores session data locally for resumption across multiple engagements.

## Installation

```bash
sudo apt install pacu
```

Alternative:

```bash
pip3 install pacu
```

## Parameter Reference

### Interactive Commands

| Parameter | Description |
|------|------|
| `import_keys <profile>` | Import AWS keys from a named AWS CLI profile |
| `set_keys` | Manually enter AWS access key, secret key, and optional session token |
| `swap_keys` | Switch between stored key sets in the current session |
| `run <module>` | Execute a specific module |
| `list` | List all available modules |
| `search <term>` | Search modules by keyword |
| `services` | List AWS services targeted by available modules |
| `data <service>` | Display enumerated data for a specific service |
| `regions` | List or set target AWS regions |
| `whoami` | Display current IAM identity and session info |
| `help <module>` | Show detailed help for a specific module |
| `sessions` | List, create, or switch sessions |

### Key Modules

| Parameter | Description |
|------|------|
| `iam__enum_users_roles_policies_groups` | Enumerate IAM users, roles, policies, and groups |
| `iam__enum_permissions` | Enumerate permissions for the current user |
| `iam__privesc_scan` | Scan for privilege escalation paths |
| `iam__backdoor_users_keys` | Create backdoor access keys on IAM users |
| `ec2__enum` | Enumerate EC2 instances, security groups, and VPCs |
| `s3__download_bucket` | Enumerate and download files from S3 buckets |
| `lambda__enum` | Enumerate Lambda functions and their configurations |
| `ebs__enum_volumes_snapshots` | Enumerate EBS volumes and snapshots |
| `rds__enum` | Enumerate RDS instances and snapshots |

## Common Commands

```bash
# Launch pacu and create a new session
pacu

# Import AWS keys from CLI profile
import_keys my-profile

# Check current identity
whoami

# Enumerate IAM users, roles, policies, and groups
run iam__enum_users_roles_policies_groups

# Check current user permissions
run iam__enum_permissions

# Scan for privilege escalation paths
run iam__privesc_scan

# Enumerate EC2 instances
run ec2__enum

# Enumerate and download files from S3 buckets
run s3__download_bucket

# Enumerate Lambda functions
run lambda__enum

# View collected data for a service
data iam
```

## Notes & Tips

1. Always run `whoami` first to confirm the identity and permissions of the imported keys before running enumeration modules.
2. The `iam__privesc_scan` module checks for over 20 known privilege escalation paths — run it early to identify quick wins.
3. Session data persists in a local SQLite database — use `sessions` to resume previous engagements or switch between targets.
4. Modules can generate significant API activity — AWS CloudTrail logs all API calls. Coordinate with the engagement scope and consider rate limiting.
5. Use `data <service>` to review collected information before running additional modules — avoids redundant API calls.

---

## Official References

- [Pacu GitHub](https://github.com/RhinoSecurityLabs/pacu)
- [Kali pacu](https://www.kali.org/tools/pacu/)
