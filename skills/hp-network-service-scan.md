---
name: network-service-scan
description: Use when you need to find what ports and services are actually open and reachable on hosts you own — the traditional infra-layer pentest step, distinct from application-layer testing. Good for catching forgotten admin panels, exposed databases, and default-credential services.
---

# Network & service scan

## Prerequisites

- `nmap`, `naabu` (faster, good for wide ranges first before nmap's deeper service detection)
- IP/host list — from `attack-surface-recon` or provided directly

## Workflow

1. **Fast initial port sweep** across the full range to find what's open before spending time on deep scans:
   ```bash
   naabu -host targets.txt -top-ports 1000 -o findings/naabu.txt
   ```

2. **Deep service/version detection on discovered open ports:**
   ```bash
   nmap -sV -sC -p $(cat findings/naabu.txt | cut -d: -f2 | sort -u | tr '\n' ',') -oA findings/nmap-detail <target>
   ```
   `-sC` runs nmap's default script set — safe enough for general use, includes banner grabbing and common misconfig checks.

3. **Flag anything that shouldn't be internet-facing at all.** These are common, high-severity findings independent of whether the service itself has a known CVE:
   - Databases directly reachable (Postgres 5432, MySQL 3306, MongoDB 27017, Redis 6379, Elasticsearch 9200) without a VPN/private-network boundary
   - Admin/ops tooling exposed (Jenkins, Grafana, Kibana, phpMyAdmin, unauthenticated Docker API on 2375, Kubernetes API/dashboard)
   - Remote access services with weak exposure (SSH on default port with password auth still enabled, RDP directly reachable)
   - Anything answering on a non-standard port that doesn't match what's expected — could indicate an unmanaged/shadow service

4. **Check for default or weak credentials** on any exposed service identified above — don't brute-force, just try documented defaults for that specific product/version (e.g., Redis with no `requirepass` set at all is a more common and more severe finding than a weak password).

5. **Cross-reference nmap's version output against known CVEs** for that exact version — feed into `dependency-audit`'s reachability logic or run targeted `nuclei -tags cve` templates against confirmed service versions.

## Output

`findings/naabu.txt`, `findings/nmap-detail.*`. Report per finding: host, port, service+version, why it's a problem (unnecessary exposure vs. known CVE vs. default creds), fix (firewall rule, VPN-only binding, patch, credential rotation).

## Notes

- Only scan hosts you own or are explicitly authorized to test — this is active, potentially noisy traffic and can trip IDS/IPS or abuse-detection on infrastructure you don't control.
- An open port with no vulnerable service behind it still increases attack surface — "close it if it's not needed" is a valid finding even without a CVE attached.
