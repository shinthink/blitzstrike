# ngrep

- **Category**: Sniffing & Spoofing / Packet Analysis
- **Risk Level**: 🟡 Medium

---

## Description

Network grep — applies regex pattern matching against network packet payloads. Captures live traffic or reads pcap files and filters packets whose content matches a specified pattern. Combines BPF filters for protocol-level selection with content-level regex matching, making it ideal for finding specific strings (credentials, tokens, API keys) in network traffic. Supports pcap output for integration with other analysis tools.

## Installation

```bash
sudo apt install ngrep
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<pattern>` | Regex pattern to match against packet payloads (positional) |
| `<filter>` | BPF filter expression for protocol-level filtering (positional, after pattern) |
| `-i` | Ignore case |
| `-q` | Be quiet (don't print packet reception hash marks) |
| `-W byline` | Set the dump format (normal, byline, single, none) |
| `-d <device>` | Use specified device instead of the pcap default |
| `-I <pcap_file>` | Read packet stream from pcap format file |
| `-O <output_pcap>` | Write matched packets to a pcap file |
| `-n <count>` | Look at only this number of packets |
| `-T` | Print delta timestamp every time a packet is matched |
| `-t` | Print timestamp for each matched packet |
| `-x` | Print in alternate hexdump format |
| `-X` | Interpret match expression as hexadecimal |
| `-v` | Invert match (show packets NOT matching pattern) |
| `-w` | Word-regex matching |

## Common Commands

```bash
# Search for a string in live HTTP traffic
sudo ngrep -q -W byline 'password' 'tcp port 80'

# Case-insensitive search for credentials in all traffic
sudo ngrep -q -i 'user|pass|login|token' -d eth0

# Search for a pattern in a pcap file
ngrep -q -I capture.pcap 'Authorization'

# Monitor HTTP requests with readable output
sudo ngrep -q -W byline 'GET|POST|PUT|DELETE' 'tcp port 80'

# Capture SIP traffic (VoIP)
sudo ngrep -q -W byline '' 'udp port 5060'

# Match and save packets to pcap file
sudo ngrep -q -O matched.pcap 'api_key' 'tcp port 443'

# Stop after capturing 50 matching packets
sudo ngrep -q -n 50 'secret' 'tcp port 8080'

# Hex dump of matched packets
sudo ngrep -q -x 'password' 'tcp port 21'

# Match a hex pattern (e.g., HTTP/1.1 200)
sudo ngrep -q -X '485454502f312e3120323030'

# Show timestamps for matched packets
sudo ngrep -q -t 'Set-Cookie' 'tcp port 80'

# Filter DNS queries for a specific domain
sudo ngrep -q 'example.com' 'udp port 53'

# Monitor SMTP traffic for email content
sudo ngrep -q -W byline '' 'tcp port 25'
```

## Notes & Tips

1. Requires root privileges for live packet capture — use `sudo` or run as root.
2. ngrep searches packet payloads, not headers — combine with BPF filters (`tcp port 80`, `host 192.168.1.1`) to narrow traffic before pattern matching.
3. The `-W byline` flag is essential for readable HTTP traffic — without it, entire payloads are printed on a single line.
4. Does not decrypt TLS/SSL traffic — only effective against plaintext protocols (HTTP, FTP, SMTP, DNS, SIP) or already-decrypted pcap files.
5. For high-traffic environments, always combine a pattern with a BPF filter to avoid performance degradation from matching against every packet.

---

## Official References

- [ngrep (GitHub)](https://github.com/jpr5/ngrep)
- [Kali ngrep](https://www.kali.org/tools/ngrep/)
