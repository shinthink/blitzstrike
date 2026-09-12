# AzureHound

- **Category**: Cloud-Native / Azure
- **Risk Level**: 🔴 High

---

## Description

azurehound collects Azure Active Directory and Azure Resource Manager data for BloodHound CE. It maps attack paths through Azure tenants by enumerating users, groups, applications, service principals, subscriptions, resource groups, VMs, key vaults, and role assignments. The Azure counterpart of SharpHound for on-premises Active Directory. Written in Go, it outputs JSON files that can be ingested directly into BloodHound CE for graph-based attack path analysis.

## Installation

```bash
sudo apt install azurehound
```

Alternative (from GitHub releases):

```bash
wget https://github.com/SpecterOps/AzureHound/releases/latest/download/azurehound-linux-amd64.zip
unzip azurehound-linux-amd64.zip
chmod +x azurehound
sudo mv azurehound /usr/local/bin/
```

## Parameter Reference

### Top-Level Flags

| Parameter | Description |
|-----------|-------------|
| `-c, --config <file>` | AzureHound configuration file (default: ~/.config/azurehound/config.json) |
| `-j, --jwt <token>` | Use an acquired JWT to authenticate into Azure |
| `-r, --refresh-token <token>` | Use an acquired refresh token to authenticate into Azure |
| `--json` | Output logs as JSON |
| `--log-file <file>` | Output logs to this file |
| `--proxy <url>` | Sets the proxy URL for the AzureHound service |
| `-U, --user-agent <string>` | Custom User-Agent header |
| `-v, --verbosity <int>` | Verbosity level (default 0) [Min: -1, Max: 2] |

### Subcommands

| Subcommand | Description |
|-----------|-------------|
| `list` | Lists Azure Objects (data collection for BloodHound CE) |
| `start` | Start Azure data collection service for BloodHound Enterprise |
| `configure` | Configure AzureHound |

### `list` Subcommand

Collects Azure data. Supports collecting specific object types:

| Usage | Description |
|-----------|-------------|
| `list` | Collect all Azure data |
| `list az-rm` | Collect Azure Resource Manager data |
| `list az-ad` | Collect Azure Active Directory data |
| `list az-ad --users` | Collect only user objects |
| `list az-ad --groups` | Collect only group objects |
| `list az-ad --apps` | Collect only application objects |
| `list az-ad --service-principals` | Collect only service principal objects |
| `-o, --output <file>` | Output file path (JSON format, `list` subcommand flag) |

## Common Commands

### Scenario 1: Authenticate with JWT and collect all data

```bash
# Authenticate with a JWT token and collect all data
azurehound -j <jwt-token> list -o output.json

# Authenticate with a refresh token
azurehound -r <refresh-token> list -o output.json
```

### Scenario 2: Collect specific data types

```bash
# Collect only Azure AD data
azurehound -j <jwt-token> list az-ad -o azuread.json

# Collect only Azure Resource Manager data
azurehound -j <jwt-token> list az-rm -o azurerm.json

# Collect only users
azurehound -j <jwt-token> list az-ad --users -o users.json
```

### Scenario 3: Use configuration file

```bash
# Run with a config file (configure credentials via `azurehound configure` first)
azurehound -c config.json list -o output.json
```

### Scenario 4: Ingest into BloodHound CE

```bash
# Upload collected data to BloodHound CE via API
curl -X POST https://<bloodhound-ce>/api/v2/file-upload \
  -H "Authorization: Bearer <api-token>" \
  -F "file=@output.json"
```

## Notes & Tips

1. azurehound requires at minimum Reader permissions on the target tenant to enumerate objects. The more permissions the authenticated principal has, the more complete the collection.
2. Collected JSON output is designed for BloodHound CE (Community Edition) — ensure your BloodHound instance is updated to a version that supports Azure data ingestion.
3. For automated collection, use a configuration file (`-c`) with pre-configured credentials rather than passing them on the command line. Use `azurehound configure` to set up the config interactively.
4. Collection generates Azure AD audit log entries — coordinate with the engagement scope and monitor for detection.
5. Tenant configuration is handled via the config file or the `list` subcommand flags — there is no top-level `--tenant` flag.

---

## Official References

- [AzureHound (GitHub)](https://github.com/SpecterOps/AzureHound)
- [azurehound — Kali Tools](https://www.kali.org/tools/azurehound/)
