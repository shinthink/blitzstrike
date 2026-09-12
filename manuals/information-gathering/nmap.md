# Nmap

- **Category**: Information Gathering / Port Scanning / Service Probing
- **Risk Level**: 🟡 Medium

---

## Description

Nmap is the most widely used open-source network scanning tool, developed by Gordon Lyon (Fyodor). It discovers hosts and services on a network by sending specific packets and analyzing responses, obtaining OS information, version information, and more.

## Installation

```bash
sudo apt install nmap
```

## Parameter Reference

### Target Specification

| Parameter | Description |
|-----------|-------------|
| `target` | Hostname/IP/CIDR/range Example: `192.168.1.1`, `192.168.1.0/24` |
| `-iL <file>` | Input from list of hosts/networks |
| `--exclude <host>` | Exclude hosts/networks |
| `--excludefile <file>` | Exclude list from file |

### Host Discovery

| Parameter | Description |
|-----------|-------------|
| `-sn` | Ping Scan - disable port scan |
| `-Pn` | Skip host discovery, assume all hosts are alive |
| `-PS[ports]` | TCP SYN Ping to given ports |
| `-PA[ports]` | TCP ACK Ping |
| `-PU[ports]` | UDP Ping |
| `-PE` | ICMP echo, timestamp, and netmask request discovery probes |
| `-PP` | ICMP Timestamp Ping |
| `-PM` | ICMP Address Mask Ping |
| `--disable-arp-ping` | Disable ARP Ping |
| `-6` | Enable IPv6 scanning |

### Port Scan Techniques

| Parameter | Description |
|-----------|-------------|
| `-sL` | List Scan - simply list targets to scan |
| `-sS` | TCP SYN/Connect()/ACK/Window/Maimon scans |
| `-sT` | TCP Connect scan (full three-way handshake) |
| `-sU` | UDP scan |
| `-sA` | TCP ACK scan (detects firewall rules) |
| `-sW` | TCP Window scan |
| `-sM` | TCP Maimon scan |
| `-sN` | TCP Null, FIN, and Xmas scans |
| `-sF` | TCP FIN scan |
| `-sX` | TCP Xmas scan |
| `-sI <zombie>` | Idle scan (zombie scan) |
| `-sY` | SCTP INIT/COOKIE-ECHO scans |
| `-sZ` | SCTP COOKIE-ECHO scan |
| `-sO` | IP protocol scan |
| `-b <FTP relay>` | FTP Bounce scan |

### Port Range

| Parameter | Description |
|-----------|-------------|
| `-p <port>` | Only scan specified ports |
| `-p-` | Scan all ports (1-65535) |
| `--top-ports <n>` | Scan the n most common ports Example: `--top-ports 100` |
| `-F` | Fast mode - scan fewer ports than the default scan |
| `-r` | Scan ports sequentially |

### Service/Version Detection

| Parameter | Description |
|-----------|-------------|
| `-sV` | Probe open ports to determine service/version info |
| `--version-intensity <0-9>` | Set from 0 (light) to 9 (try all probes) |
| `--version-light` | Limit to most likely probes (intensity 2) |
| `--version-all` | Try every single probe (intensity 9) |

### Aggressive Mode

| Parameter | Description |
|-----------|-------------|
| `-A` | Enable OS detection, version detection, script scanning, and traceroute |

### OS Detection

| Parameter | Description |
|-----------|-------------|
| `-O` | Enable OS detection |
| `--osscan-limit` | Limit OS detection to promising targets |
| `--osscan-guess` | Guess OS more aggressively |

### NSE Scripts

| Parameter | Description |
|-----------|-------------|
| `-sC` | Equivalent to --script=default |
| `--script=<script>` | Comma separated list of scripts, directories, or categories |
| `--script=<category>` | Run scripts in a category Example: `--script=vuln` |
| `--script-args=<args>` | Provide arguments to scripts |
| `--script-updatedb` | Update script database |

### Timing and Performance

| Parameter | Description |
|-----------|-------------|
| `-T0` | Paranoid mode (slowest, IDS evasion) |
| `-T1` | Sneaky mode |
| `-T2` | Polite mode |
| `-T3` | Normal mode (default) |
| `-T4` | Aggressive mode (recommended for LAN) |
| `-T5` | Insane mode (fastest, may be inaccurate) |
| `--min-rate <n>` | Send packets no slower than this number per second |
| `--max-rate <n>` | Send packets no faster than this number per second |
| `--min-parallelism <n>` | Probe parallelization |
| `--max-parallelism <n>` | Maximum parallel probes |
| `--max-retries <n>` | Caps number of port scan probe retransmissions |

### Firewall/IDS Evasion

| Parameter | Description |
|-----------|-------------|
| `-f` | Fragment packets |
| `--mtu <size>` | Set MTU |
| `-D <decoy1,decoy2>` | Cloak a scan with decoys |
| `-S <IP>` | Spoof source address |
| `-e <interface>` | Use specified interface |
| `--source-port <port>` | Spoof source port |
| `--data-length <length>` | Append random data to sent packets |
| `--ip-options <options>` | Send packets with specified IP options |
| `--ttl <value>` | Set IP time-to-live field |
| `--spoof-mac <MAC>` | Spoof your MAC address |
| `--badsum` | Send packets with a bogus TCP/UDP/SCTP checksum |

### Output Formats

| Parameter | Description |
|-----------|-------------|
| `-oN <file>` | Output scan in normal format |
| `-oX <file>` | XML output |
| `-oG <file>` | Grepable output |
| `-oA <basename>` | Output in the three major formats at once |
| `-v` | Increase verbosity |
| `-vv` | More verbose |
| `--reason` | Display the reason a port is in a particular state |
| `--open` | Only show open ports |
| `--packet-trace` | Show all packets |
| `-d` | Increase debugging level (use -dd or more for greater effect) |

## Common Commands

### Scenario 1: Quick Host Discovery

```bash
# Discover live hosts on LAN
nmap -sn 192.168.1.0/24

# Specify multiple subnets
nmap -sn 192.168.1.0/24 10.0.0.0/24

# Read targets from file
nmap -sn -iL targets.txt

# Disable DNS resolution (speed up)
nmap -sn -n 192.168.1.0/24
```

### Scenario 2: Basic Port Scanning

```bash
# Scan default 1000 common ports
nmap 192.168.1.100

# Scan all 65535 ports
nmap -p- 192.168.1.100

# Scan specified ports
nmap -p 22,80,443,3306,8080 192.168.1.100

# Scan top 1000 common ports (including UDP)
nmap -sU -sS --top-ports 1000 192.168.1.100

# Quick scan (100 ports)
nmap -F 192.168.1.100
```

### Scenario 3: Service Version and OS Detection

```bash
# Standard reconnaissance scan
nmap -sV -O 192.168.1.100

# Aggressive mode (includes scripts, version, OS, traceroute)
nmap -A 192.168.1.100

# Detailed version detection
nmap -sV --version-all 192.168.1.100
```

### Scenario 4: Using NSE Scripts

```bash
# Run default scripts
nmap -sC 192.168.1.100

# Vulnerability detection
nmap --script=vuln 192.168.1.100

# HTTP information gathering
nmap --script=http-title,http-headers,http-methods 192.168.1.100

# SMB vulnerability detection
nmap --script=smb-vuln* 192.168.1.100

# SSL certificate info
nmap --script=ssl-cert -p 443 192.168.1.100

# Detect Heartbleed
nmap --script=ssl-heartbleed -p 443 192.168.1.100

# FTP anonymous login detection
nmap --script=ftp-anon -p 21 192.168.1.100

# SSH brute force
nmap --script=ssh-brute -p 22 192.168.1.100

# DNS zone transfer
nmap --script=dns-zone-transfer --script-args dns-zone-transfer.domain=example.com -p 53 ns1.example.com
```

### Scenario 5: Stealth Scanning (Evading Detection)

```bash
# Use decoy IPs to mask scan
nmap -D RND:10 192.168.1.100

# Slow scan (evade IDS)
nmap -T1 192.168.1.100

# Fragment packets
nmap -f 192.168.1.100

# Randomize target order
nmap --randomize-hosts 192.168.1.0/24

# Spoof source port (pretend to be web traffic on port 80)
nmap --source-port 80 192.168.1.100
```

### Scenario 6: Comprehensive Reconnaissance

```bash
# Full reconnaissance (commonly used in CTF and authorized testing)
nmap -sS -sV -sC -O -p- --min-rate 5000 -oA scan_result 192.168.1.100

# Fast full-port scan + detailed version detection
nmap -sS -p- --min-rate 10000 -oN allports.txt 192.168.1.100
nmap -sV -sC -p $(grep open allports.txt | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//') 192.168.1.100

# Enterprise network reconnaissance
nmap -sn 10.0.0.0/8 -oG hosts.txt
grep Up hosts.txt | cut -d' ' -f2 > live_hosts.txt
nmap -sS -sV --top-ports 1000 -iL live_hosts.txt -oA enterprise_scan
```

### Scenario 7: Special Protocol Scanning

```bash
# UDP scan (important services: DNS 53, SNMP 161, NTP 123)
nmap -sU -p 53,67,68,69,123,161,162 192.168.1.100

# SCTP scan
nmap -sY 192.168.1.100

# IP protocol scan (probe supported IP protocols)
nmap -sO 192.168.1.100
```

## Notes & Tips

1. SYN scan (`-sS`), OS detection (`-O`), and aggressive mode (`-A`) require root privileges. Connect scan (`-sT`) does not require root but leaves more traces.
2. If all ports show as `filtered`, a firewall is likely present — try `-Pn` to skip host discovery.
3. UDP scanning is inherently unreliable; combine with `-sV` for better accuracy.
4. Use `-T4 --min-rate 5000` for fast LAN scanning; add `-n` to skip DNS resolution for additional speed.
5. When `open|filtered` appears (common in UDP/FIN/Null/Xmas scans), re-test with `-sT` to confirm.
6. NSE script categories: `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`. The `dos` and `exploit` categories are dangerous — use only with explicit authorization.

---

## Official References

- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Nmap NSE Scripts](https://nmap.org/nsedoc/)
- [Nmap Official Site](https://nmap.org/)
