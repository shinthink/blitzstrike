# CloudBrute

- **Category**: Information Gathering / Cloud Asset Discovery
- **Risk Level**: 🟢 Low

---

## Description

CloudBrute discovers cloud infrastructure by brute-forcing cloud provider resources with target keywords. It supports multiple providers and is useful for finding public storage buckets, apps, databases, and other cloud services that follow predictable naming patterns. Use it as a focused cloud asset discovery tool when cloud resources are explicitly in scope.

## Installation

```bash
sudo apt update
sudo apt install cloudbrute
cloudbrute -h
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-d <domain>` | Target domain or keyword basis |
| `-k <keyword>` | Keyword used to generate URLs |
| `-w <file>` | Wordlist for brute-force |
| `-c <provider>` | Force a search on a specific cloud provider (check config.yaml providers list) |
| `-m <mode>` | Search mode: `storage` (default) or `app` |
| `-o <file>` | Output file |
| `-t <n>` | Threads (default: 80) |
| `-T <n>` | Timeout per request in seconds (default: 10) |
| `-p <file>` | Proxy list file |
| `-a` | Use random user-agent |
| `-D` | Enable debug mode |
| `-q` | Suppress output |
| `-C <dir>` | Config folder path |
| `-h` | Print help information |

## Common Commands

```bash
# Show supported options and providers for the installed version
cloudbrute -h

# Brute-force cloud assets from a company keyword
cloudbrute -k examplecorp -w words.txt -o /tmp/cloudbrute.txt

# Use domain-derived keyword variants
cloudbrute -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o /tmp/cloudbrute-domain.txt

# Increase threads for a controlled internal/lab scope
cloudbrute -k examplecorp -w words.txt -t 20 -o /tmp/cloudbrute-fast.txt
```

## Notes & Tips

1. Check `cloudbrute -h` first; flags and provider names vary by packaged version.
2. Use smaller, organization-specific wordlists before broad public lists.
3. Treat discovered public resources as leads; verify authorization before accessing data.
4. Pair with `cloud-enum` because the tools use different provider checks and naming strategies.

---

## Official References

- [CloudBrute GitHub](https://github.com/0xsha/CloudBrute)
- [Kali cloudbrute](https://www.kali.org/tools/cloudbrute/)
