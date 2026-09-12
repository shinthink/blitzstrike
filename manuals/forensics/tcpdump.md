# tcpdump

- **Category**: Forensics / Traffic Analysis
- **Risk Level**: 🟢 Low

---

## Description

A command-line packet analyzer pre-installed on virtually all Linux systems. Captures live network traffic or reads from pcap files, with powerful BPF (Berkeley Packet Filter) expression syntax for precise filtering. In penetration testing, used to capture credentials over plaintext protocols, analyze traffic, and create capture files for offline analysis in Wireshark. The primary traffic analysis tool in headless and server environments where Wireshark's GUI is unavailable.

## Installation

```bash
sudo apt install tcpdump
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-i <interface>` | Network interface to capture on (`any` for all interfaces) |
| `-w <file>` | Write captured packets to pcap file |
| `-r <file>` | Read packets from a pcap file |
| `-n` | Do not resolve hostnames |
| `-nn` | Do not resolve hostnames or port names |
| `-v / -vv / -vvv` | Verbose output (increasing detail) |
| `-c <n>` | Stop after capturing n packets |
| `-s <n>` | Snapshot length in bytes (0 = full packet) |
| `-A` | Print packet payload as ASCII |
| `-X` | Print packet in hex and ASCII |
| `-l` | Line-buffered output (for piping) |
| `port <n>` | Filter by port number |
| `host <ip>` | Filter by source or destination IP |
| `net <cidr>` | Filter by network |
| `tcp / udp / icmp` | Filter by protocol |
| `-C <size>` | Rotate capture files by size (MB) |
| `-G <seconds>` | Rotate capture files by time interval |

## Common Commands

```bash
# Capture all traffic on eth0 and save to file
tcpdump -i eth0 -w capture.pcap

# Display HTTP traffic as ASCII (credential sniffing)
tcpdump -i eth0 -A -nn port 80

# Capture traffic to/from a specific host
tcpdump -i eth0 host 192.168.1.10 -w target.pcap

# Capture DNS queries only
tcpdump -i any -nn port 53

# Read a pcap file and display
tcpdump -r capture.pcap -nn

# Capture FTP credentials (plaintext protocol)
tcpdump -i eth0 -A -nn port 21

# Capture from any interface (useful in Docker/headless)
tcpdump -i any -nn -w capture.pcap

# Stop after 1000 packets
tcpdump -i eth0 -c 1000 -w capture.pcap

# Live output suitable for piping to grep
tcpdump -i eth0 -l -A -nn port 80 | grep -i "user\|pass"
```

## Notes & Tips

1. Always use `-nn` to avoid DNS lookups slowing down captures.
2. Capture to file with `-w` and analyze offline in Wireshark for complex protocols.
3. In Docker and headless environments, tcpdump is the primary traffic analysis tool — Wireshark's GUI is unavailable.
4. Combine with `strings` or `grep` for quick plaintext credential extraction: `tcpdump -A port 21 | grep -i "USER\|PASS"`.
5. tcpdump capture files (pcap/pcapng) are fully compatible with Wireshark for later GUI analysis.

---

## Official References

- [tcpdump man page](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [Kali tcpdump](https://www.kali.org/tools/tcpdump/)
