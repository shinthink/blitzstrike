# DNSChef

- **Category**: Sniffing & Spoofing / DNS Spoofing
- **Risk Level**: 🔴 High

---

## Description

A highly configurable DNS proxy for penetration testers and malware analysts. Acts as a rogue DNS server, allowing selective spoofing of DNS responses for specific domains while transparently forwarding all other requests. Supports A, AAAA, MX, CNAME, NS, TXT, SOA, and other record types. Useful for redirecting traffic to attacker-controlled hosts during MITM attacks, phishing simulations, and malware C2 analysis.

## Installation

```bash
sudo apt install dnschef
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `--fakeip <IP>` | IP address to respond with for A record queries |
| `--fakeipv6 <IPv6>` | IPv6 address for AAAA record queries |
| `--fakemail <host>` | Fake mail server hostname for MX queries |
| `--fakealias <host>` | Fake CNAME alias |
| `--fakens <host>` | Fake nameserver for NS queries |
| `--file <file>` | Specify a configuration file with domain-specific spoofing rules |
| `-i <IP>` | Interface IP to listen on (default: 127.0.0.1) |
| `-p <port>` | DNS port to listen on (default: 53) |
| `--nameservers <IPs>` | Upstream DNS servers for non-spoofed queries (comma-separated) |
| `-q` | Quiet mode — suppress headers |
| `--logfile <file>` | Log queries to file |

## Common Commands

```bash
# Spoof all DNS A records to attacker IP
sudo dnschef --fakeip 192.168.1.100 -i 0.0.0.0

# Spoof specific domain only
sudo dnschef --fakeip 192.168.1.100 --fakedomains example.com -i 0.0.0.0

# Spoof multiple record types
sudo dnschef --fakeip 192.168.1.100 --fakemail mail.evil.com --fakens ns.evil.com -i 0.0.0.0

# Use a configuration file for granular control
sudo dnschef --file dns_rules.ini -i 0.0.0.0

# Log all DNS queries to file
sudo dnschef --fakeip 192.168.1.100 -i 0.0.0.0 --logfile dns_queries.log

# Use custom upstream DNS server
sudo dnschef --fakeip 192.168.1.100 --nameservers 8.8.8.8 -i 0.0.0.0
```

### Configuration File Format

```ini
# dns_rules.ini
[A]
*.example.com=192.168.1.100
login.target.com=192.168.1.100

[MX]
example.com=mail.evil.com
```

## Notes & Tips

1. Requires root privileges to bind to port 53.
2. Use with `iptables` or `bettercap` to redirect victim DNS traffic to DNSChef — e.g., via ARP spoofing + DNS port redirect.
3. The `--file` option is essential for selective spoofing — wildcard matching (`*.example.com`) allows fine-grained domain control.
4. Non-spoofed domains are transparently forwarded to upstream DNS, making the proxy invisible for non-targeted traffic.
5. Combine with `mitmproxy` or `bettercap` to intercept redirected HTTP/S traffic after DNS spoofing.

---

## Official References

- [DNSChef (GitHub)](https://github.com/iphelix/dnschef)
- [Kali DNSChef](https://www.kali.org/tools/dnschef/)
