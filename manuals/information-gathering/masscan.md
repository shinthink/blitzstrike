# Masscan

- **Category**: Information Gathering / Port Scanning
- **Risk Level**: 🔴 High

---

## Description

Masscan is the world's fastest port scanner, capable of scanning the entire internet (all IPv4 hosts on a single port) in under 5 minutes, transmitting 10 million packets per second from a single machine. It uses an asynchronous transmission mechanism and achieves extremely high packet sending rates through a custom TCP/IP protocol stack.

## Installation

```bash
masscan --version

sudo apt install masscan

# Compile from source
git clone https://github.com/robertdavidgraham/masscan
cd masscan && make && make install
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-p <port>` | Specify port range Example: `-p 80`, `-p 0-65535` |
| `--rate <rate>` | Packet send rate (packets/sec) Example: `--rate 10000` |
| `-oX <file>` | XML output Example: `-oX scan.xml` |
| `-oL <file>` | List format output Example: `-oL scan.txt` |
| `-oJ <file>` | JSON output Example: `-oJ scan.json` |
| `-oB <file>` | Binary output (resumable) Example: `-oB scan.bin` |
| `--banners` | Capture banner information |
| `--http-user-agent` | Custom HTTP User-Agent |
| `-e <interface>` | Specify network interface Example: `-e eth0` |
| `--router-mac <MAC>` | Specify router MAC |
| `--adapter-mac <MAC>` | Specify local MAC |
| `--source-ip <IP>` | Specify source IP |
| `--source-port <port>` | Specify source port range |
| `--retries <count>` | Number of retries Example: `--retries 1` |
| `--wait <sec>` | Wait time after scanning Example: `--wait 10` |
| `--offline` | Offline test mode |
| `-c <config>` | Use configuration file |
| `--resume <file>` | Resume interrupted scan |
| `--shard <n>/<total>` | Sharded scanning Example: `--shard 1/4` |
| `--include-file <file>` | Read targets from file |
| `--exclude <IP>` | Exclude IP |
| `--excludefile <file>` | Exclusion file |
| `--ping` | Send ICMP Echo |

## Common Commands

### Basic Scanning

```bash
# Scan all ports on a single IP (rate 1000/s)
masscan -p0-65535 192.168.1.100 --rate=1000

# Scan common ports on a subnet
masscan -p80,443,22,21,3389 192.168.1.0/24 --rate=10000

# Scan all ports on an entire subnet
masscan -p0-65535 192.168.1.0/24 --rate=5000 -oL results.txt
```

### Fast Scanning

```bash
# High-speed internal network scan
masscan -p0-65535 10.0.0.0/8 --rate=100000 -oX scan.xml

# Ultra-fast web port scan
masscan -p80,8080,443,8443 192.168.0.0/16 --rate=50000
```

### Output and Saving

```bash
# Save in multiple formats
# Note: masscan only supports ONE output file per run; run twice for multiple formats
masscan -p0-65535 192.168.1.0/24 --rate=1000 -oX scan.xml
masscan -p0-65535 192.168.1.0/24 --rate=1000 -oL scan.txt

# Capture banners
masscan -p80,443 192.168.1.0/24 --rate=1000 --banners -oL banners.txt

# Resume after interruption
# Press Ctrl+C during scan → masscan auto-saves state to 'paused.conf'
masscan -p0-65535 192.168.1.0/24 --rate=1000  # press Ctrl+C to pause
masscan --resume paused.conf  # Resume from checkpoint

# -oB creates a parseable binary results file (NOT a resume checkpoint):
masscan -p0-65535 192.168.1.0/24 --rate=1000 -oB scan.bin
# To convert -oB output later: masscan --readscan scan.bin -oJ scan.json
```

### Integration with Nmap

```bash
# Use masscan to quickly find open ports, then nmap for detailed probing
masscan -p0-65535 192.168.1.100 --rate=10000 -oL ports.txt
# Extract port list
ports=$(grep "open" ports.txt | awk '{print $3}' | cut -d'/' -f1 | sort -u | tr '\n' ',' | sed 's/,$//')
# Detailed probing with nmap
nmap -sV -sC -p $ports 192.168.1.100
```

## Notes & Tips

1. **Root privileges required**: Direct raw socket operations require root
2. **Rate control**: Control the rate in production environments to avoid network congestion; `--rate=1000` is a safe starting point
3. **Network devices**: High-speed scanning may overload routers and firewalls
4. **Legal authorization**: Only use within authorized scope; high-speed scanning is very easy to detect

---

## Official References

- [masscan GitHub](https://github.com/robertdavidgraham/masscan)
