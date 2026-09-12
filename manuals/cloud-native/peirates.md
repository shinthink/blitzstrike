# Peirates

- **Category**: Cloud-Native / Kubernetes Exploitation
- **Risk Level**: 🔴 Critical

---

## Description

peirates is a Kubernetes penetration testing tool designed to run from within a compromised container. It performs privilege escalation, lateral movement, and credential harvesting within Kubernetes clusters. Capabilities include stealing service account tokens, executing commands in other pods, mounting secrets, creating privileged pods, accessing cloud provider metadata services, and pivoting between namespaces. Written in Go with an interactive menu-driven interface.

## Installation

```bash
sudo apt install peirates
```

Alternative (from GitHub releases):

```bash
wget https://github.com/inguardians/peirates/releases/latest/download/peirates-linux-amd64.tar.xz
tar xf peirates-linux-amd64.tar.xz
chmod +x peirates
sudo mv peirates /usr/local/bin/
```

## Parameter Reference

### Interactive Menu Options

> Verified against the live menu of Peirates **v1.1.28**. Each entry shows the menu number and the typed command alias(es). Items marked `*` accept the `-m <module>` command-line flag for non-interactive use.

| # | Command alias(es) | Description |
|---|-------------------|-------------|
| 1 | `sa-menu` (`list-sa`*, `switch-sa`, `get-sa`) | List, maintain, or switch service account contexts |
| 2 | `ns-menu` (`list-ns`, `switch-ns`, `get-ns`) | List and/or change namespaces |
| 3 | `list-pods`, `get-pods` | Get list of pods in current namespace |
| 4 | `dump-pod-info` | Get complete info on all pods (JSON) |
| 5 | `find-volume-mounts` | Check all pods for volume mounts |
| 6 | `aws-enter-credentials` | Enter AWS IAM credentials manually |
| 7 | `aws-assume-role` | Attempt to assume a different AWS role |
| 8 | `aws-empty-assumed-role` | Deactivate assumed AWS role |
| 9 | `cert-menu` | Switch certificate-based authentication (kubelet or manual) |
| 10 | `list-secrets`, `get-secrets` | List secrets in this namespace from API server |
| 11 | `secret-to-sa` | Get a service account token from a secret |
| 12 | `aws-get-token` * | Request IAM credentials from AWS Metadata API |
| 13 | `gcp-get-token` * | Request IAM credentials from GCP Metadata API |
| 14 | `gcp-attack-kube-env` | Request kube-env from GCP Metadata API |
| 15 | `gcp-attack-kops-gcs-1` * | Pull SA tokens from kops' GCS bucket (GCP only) |
| 16 | `attack-kops-aws-1` | Pull SA tokens from kops' S3 bucket (AWS only) |
| 17 | `aws-s3-ls` | List accessible AWS S3 buckets |
| 18 | `aws-s3-ls-objects` | List contents of an AWS S3 bucket |
| 20 | `attack-pod-hostpath-mount` | Gain a reverse rootshell on a node via a hostPath-mounting pod |
| 21 | `exec-via-api` | Run a command in one or all pods via the API server |
| 22 | `exec-via-kubelet` | Run a token-dumping command in all pods via Kubelets |
| 23 | `leakyvessels` * | Use CVE-2024-21626 (Leaky Vessels) to get a host shell (runc <1.12) |
| 30 | `nodefs-steal-secrets` | Steal secrets from the node filesystem |
| 90 | `kubectl [args]` | Run a kubectl command using the current authorization context |
| — | `kubectl-try-all [args]` | Run a kubectl command using EVERY authorization context |
| — | `kubectl-try-all-until-success [args]` | Same, but stop at the first context that works |
| 91 | `curl` | Make an HTTP request (GET or POST) to a user-specified URL |
| 92 | `set-auth-can-i` | Deactivate `auth can-i` checking before attempting actions |
| 93 | `tcpscan` | Run a simple all-ports TCP port scan against an IP address |
| 94 | `enumerate-dns` * | Enumerate services via DNS |

### Command-Line Flags

| Parameter | Description |
|-----------|-------------|
| `-k` | Ignore TLS checking on API server requests |
| `-m <module>` | Run a specific module from the menu (items marked with `*` support this) |
| `-t <token>` | JWT token for authentication |
| `-u <url>` | API server URL, e.g. `https://10.96.0.1:6443` (default is empty: `https://:`) |
| `-v` | Verbose mode — display debug messages |

## Common Commands

### Scenario 1: Launch and initial reconnaissance

```bash
# Start peirates (interactive menu)
peirates

# Start with a specific API server URL
peirates -u https://10.96.0.1:6443

# Start with a JWT token
peirates -t <jwt-token>

# Start ignoring TLS verification
peirates -k
```

### Scenario 2: Service account token operations

```bash
# Inside peirates interactive menu:

# List / switch service account contexts
sa-menu
list-sa
switch-sa

# Get a service account token from a secret
secret-to-sa
```

### Scenario 3: Namespace enumeration and secrets

```bash
# Inside peirates interactive menu:

# List pods in current namespace
list-pods

# Retrieve secrets from the current namespace
get-secrets

# Switch to a different namespace
ns-menu
```

### Scenario 4: Lateral movement & node escape

```bash
# Inside peirates interactive menu:

# Execute a command in another pod via the API server
exec-via-api

# Or dump tokens from all pods via Kubelets
exec-via-kubelet

# Gain a reverse rootshell on the node via a hostPath-mounting pod
attack-pod-hostpath-mount

# Request cloud IAM credentials from the metadata API
aws-get-token
gcp-get-token
```

### Scenario 5: Credential harvesting

```bash
# Inside peirates interactive menu:

# Steal secrets from the node filesystem
nodefs-steal-secrets

# List then read secrets from the API server
list-secrets
get-secrets

# Disable 'auth can-i' pre-checks if they block actions
set-auth-can-i
```

## Notes & Tips

1. peirates is designed to run from inside a compromised container — transfer the binary into the target pod or build a container image that includes it.
2. To harvest cloud IAM credentials, use `aws-get-token` / `gcp-get-token` (menu 12/13), which query the cloud metadata API (169.254.169.254) — effective on EKS/GKE clusters without metadata protection. `aws-enter-credentials` / `aws-assume-role` cover manual AWS credential and role-assumption workflows.
3. `nodefs-steal-secrets` (menu 30) reads secrets directly from the node filesystem; `find-volume-mounts` (menu 5) surfaces pods with interesting volume mounts.
4. Node escape is highest-impact: `attack-pod-hostpath-mount` (menu 20) launches a hostPath-mounting pod for a node rootshell, and `leakyvessels` (menu 23) abuses CVE-2024-21626 on runc <1.12. Both should be clearly scoped in the engagement authorization.
5. All actions use the currently selected service account context — use `sa-menu` to switch contexts and `kubectl-try-all` to test a command across every available context. `set-auth-can-i` disables client-side `auth can-i` pre-checks if they get in the way.

---

## Official References

- [peirates (GitHub)](https://github.com/inguardians/peirates)
- [peirates — Kali Tools](https://www.kali.org/tools/peirates/)
