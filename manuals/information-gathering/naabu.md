# Naabu

- **Category**: Information Gathering / Port Scanning
- **Risk Level**: 🟡 Medium

---

## Description

naabu is ProjectDiscovery's fast, pipeline-friendly port scanner. It is designed for large target lists, supports host discovery, top-port or custom-port scanning, JSON output, and direct chaining into `httpx` and `nuclei`. Use it when you need faster initial TCP port discovery than nmap while keeping output easy for agents to parse.

## Installation

```bash
sudo apt update
sudo apt install naabu

# Upstream Go install
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

naabu -h
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-host <host>` | Hosts to scan ports for (comma-separated) |
| `-list <file>` / `-l <file>` | List of hosts to scan ports (file) |
| `-p <ports>` | Ports to scan, such as `80,443,8000-9000` |
| `-top-ports <n>` | Top ports to scan (default 100) [full,100,1000] |
| `-rate <n>` | Packets to send per second (default 1000) |
| `-json` | Write output in JSON lines format |
| `-o <file>` | Write output to file |
| `-silent` | Display only results in output |
| `-exclude-hosts <hosts>` / `-eh <hosts>` | Exclude hosts from scan (comma-separated) |
| `-exclude-file <file>` / `-ef <file>` | List of hosts to exclude from scan (file) |
| `-nmap-cli <cmd>` | Nmap command to run on found results (e.g., 'nmap -sV') |
| `-sD` | Service discovery |
| `-sV` | Service version detection |

## Common Commands

```bash
# Scan common ports on a single host
naabu -host 192.168.1.10 -top-ports 100

# Scan a CIDR range and save host:port output
naabu -host 192.168.1.0/24 -top-ports 1000 -silent -o /tmp/naabu.txt

# Scan custom ports
naabu -list targets.txt -p 80,443,8080,8443,9000-9100 -silent

# JSON output for parsing
naabu -list targets.txt -top-ports 100 -json -o /tmp/naabu.jsonl

# Chain discovered web ports into httpx
naabu -list targets.txt -top-ports 1000 -silent | httpx -title -tech-detect

# Follow up discovered ports with nmap service detection
naabu -host 10.0.0.0/24 -top-ports 100 -nmap-cli "nmap -sV -oN /tmp/nmap-naabu.txt"
```

## Notes & Tips

1. Use naabu for fast discovery, then use nmap for service/version detection on discovered ports.
2. Keep `-rate` conservative on production networks to avoid packet loss or noisy scans.
3. `-silent` is best for Unix pipelines; `-json` is best for agent parsing.
4. For raw packet modes in Docker, use a persistent container created with `--network host --privileged`.
5. Always respect explicit scan scope when using CIDR input.

---

## Official References

- [naabu GitHub](https://github.com/projectdiscovery/naabu)
- [naabu Documentation](https://docs.projectdiscovery.io/tools/naabu/overview)
- [Kali naabu](https://www.kali.org/tools/naabu/)
