# tshark

- **Category**: Forensics / Traffic Analysis
- **Risk Level**: 🟢 Low

---

## Description

The command-line version of Wireshark. Captures and analyzes network traffic without a GUI, supporting Wireshark's powerful display filter syntax for protocol-aware filtering and field extraction. More expressive than tcpdump for complex protocol analysis — can extract specific fields from any protocol layer, follow TCP streams, and generate conversation statistics. The CLI alternative to Wireshark for automated and headless environments.

## Installation

```bash
sudo apt install wireshark
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-i <interface>` | Name or index of interface (default: first non-loopback) |
| `-r <file>` | Set the filename to read from (or '-' for stdin) |
| `-w <file>` | Write packets to a pcapng-format file (or '-' for stdout) |
| `-f <filter>` | Packet filter in libpcap filter syntax |
| `-Y <filter>` | Display filter (Wireshark syntax) |
| `-T <format>` | Output format: `ek`, `fields`, `json`, `jsonraw`, `pdml`, `ps`, `psml`, `text` |
| `-e <field>` | Field to print if -Tfields selected (e.g., `http.host`) |
| `-c <n>` | Stop after n packets |
| `-V` | Add output of packet tree (packet details) |
| `-q` | Be more quiet on stdout (e.g., when using statistics) |
| `-z <stat>` | Various statistics (see man page for details) |
| `-2` | Two-pass analysis (useful for reassembly-dependent filters) |
| `--export-objects <proto>,<dir>` | Export HTTP/SMB/etc objects to directory |

## Common Commands

```bash
# Capture all traffic on eth0
tshark -i eth0

# Capture and save to file
tshark -i eth0 -w capture.pcap

# Read pcap and display
tshark -r capture.pcap

# Filter for HTTP traffic
tshark -r capture.pcap -Y 'http'

# Extract HTTP request hostnames and URIs
tshark -r capture.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri

# Find cleartext credentials
tshark -r capture.pcap -Y 'ftp or telnet or http.authbasic'

# Capture only DNS queries live
tshark -i eth0 -Y 'dns'

# Extract FTP usernames
tshark -r capture.pcap -Y 'ftp.request.command == "USER"' -T fields -e ftp.request.arg

# Follow and reassemble TCP stream 0
tshark -r capture.pcap -q -z follow,tcp,ascii,0

# Top IP conversation statistics
tshark -r capture.pcap -q -z conv,ip
```

## Notes & Tips

1. tshark supports Wireshark's display filter syntax (`-Y`) — far more expressive than tcpdump's BPF filters for protocol-aware analysis.
2. Use `-T fields -e <field>` for machine-readable, script-friendly output; field names follow Wireshark's notation (e.g., `ip.src`, `dns.qry.name`).
3. `tshark -r file.pcap -Y 'http.authbasic'` extracts Base64-encoded HTTP Basic credentials in one command.
4. For live capture with simple BPF filters, tcpdump is lighter; use tshark when you need protocol-aware filtering or field extraction.
5. All pcap files captured by tcpdump are fully readable by tshark — they share the same pcap/pcapng format.

---

## Official References

- [tshark man page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Kali wireshark/tshark](https://www.kali.org/tools/wireshark/)
