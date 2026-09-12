# tcpflow

- **Category**: Forensics / Network Forensics
- **Risk Level**: 🟢 Low

---

## Description

Captures and reassembles TCP streams from live network traffic or pcap files. Unlike `tcpdump`, which shows individual packets, tcpflow reconstructs complete bidirectional data flows and saves each TCP connection to a separate file. Essential for extracting transferred files, HTTP sessions, email content, and other protocol data from network captures. Supports automatic decompression, MIME extraction, and various output scanners.

## Installation

```bash
sudo apt install tcpflow
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-i IFACE` | Network interface on which to listen |
| `-r FILE` | Read packets from tcpdump pcap file (may be repeated) |
| `-o DIR` | Specify output directory (default '.') |
| `-a` | Do ALL post-processing |
| `-c` | Console print only (don't create files) |
| `-C` | Console print only, without source/dest header |
| `-e SCANNER` | Enable specific scanner (e.g., http, netviz) |
| `-E SCANNER` | Turn off all scanners except the specified one |
| `-F FORMAT` | Filename prefix/suffix format (use -hh for options) |
| `-T TEMPLATE` | Filename template for output files |
| `-B` | Binary output, even with -c or -C |
| `-J` | Output in JSON format |
| `-D` | Output in hex (useful with -c or -C) |
| `-s` | Strip non-printable characters (change to '.') |
| `-g` | Output each flow in alternating colors |
| `-Z` | Do not decompress gzip-compressed HTTP transactions |
| `-b <bytes>` | Max number of bytes per flow to save |
| `-S name=value` | Set a configuration parameter |
| `FILTER` | BPF filter expression (same syntax as tcpdump) |

## Common Commands

```bash
# Reassemble TCP streams from a pcap file
tcpflow -r capture.pcap -o /tmp/flows/

# Capture live traffic on an interface
sudo tcpflow -i eth0 -o /tmp/flows/

# Reassemble streams and print to console
tcpflow -c -r capture.pcap

# Enable all scanners (HTTP decompression, MIME extraction, etc.)
tcpflow -a -r capture.pcap -o /tmp/flows/

# Filter specific host traffic from pcap
tcpflow -r capture.pcap -o /tmp/flows/ "host 192.168.1.100"

# Filter specific port (HTTP traffic only)
tcpflow -r capture.pcap -o /tmp/flows/ "port 80"

# Extract HTTP objects with all scanners enabled
tcpflow -a -r capture.pcap -o /tmp/http_extract/ "port 80 or port 443"

# Generate report with flow metadata
tcpflow -r capture.pcap -o /tmp/flows/ -g

# Live capture filtered by destination port
sudo tcpflow -i eth0 -o /tmp/flows/ "dst port 22"

# Force binary output without decompression
tcpflow -B -r capture.pcap -o /tmp/flows/
```

## Notes & Tips

1. Each TCP connection produces two output files (one per direction), named with the source/destination IP and port -- e.g., `192.168.001.100.00080-010.000.000.001.49152`.
2. Use `-a` to enable all scanners, which automatically decompress gzip/deflate HTTP content and extract MIME attachments.
3. tcpflow is non-destructive when reading pcap files. For live capture, it only captures (does not inject or modify traffic).
4. BPF filter expressions follow the same syntax as `tcpdump` and can be used to narrow captures to specific hosts, ports, or protocols.
5. The `-c` (console) option is useful for quick inspection of text-based protocols like HTTP, SMTP, and FTP control channels.
6. For large pcap files, filter by relevant hosts/ports to reduce output volume and speed up processing.
7. Output files can be directly examined with standard tools: `file`, `strings`, hex editors, or protocol-specific parsers.

---

## Official References

- [Kali tcpflow](https://www.kali.org/tools/tcpflow/)
- [tcpflow (GitHub)](https://github.com/simsong/tcpflow)
