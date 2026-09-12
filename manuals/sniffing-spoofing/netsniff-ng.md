# netsniff-ng

- **Category**: Sniffing & Spoofing / Packet Capture
- **Risk Level**: 🟡 Medium

---

## Description

A high-performance Linux network toolkit built around zero-copy packet capture. The suite includes `netsniff-ng` (packet sniffer), `trafgen` (packet generator), `astraceroute` (autonomous system traceroute), `flowtop` (connection tracker), `ifpps` (interface statistics), `bpfc` (BPF compiler), `curvetun` (encrypted tunnel), and `mausezahn` (packet fuzzer). Designed for performance-critical environments where tcpdump is too slow — achieves line-rate capture via memory-mapped I/O.

## Installation

```bash
sudo apt install netsniff-ng
```

## Parameter Reference

### netsniff-ng (sniffer)

| Parameter | Description |
|-----------|-------------|
| `-i <dev>` | Input device or pcap file |
| `-o <dev\|file>` | Output device or pcap file |
| `-f <filter>` | BPF filter expression |
| `-t, --type <type>` | Filter by packet type: `host`, `broadcast`, `multicast`, `others`, `outgoing` |
| `-s, --silent` | Do not print captured packets (statistics only) |
| `-n <count>` | Capture n packets then stop |
| `-S <size>` | Ring buffer size (KiB/MiB/GiB) |
| `-J, --jumbo-support` | Support 64KB Super Jumbo Frames (default: 2048B) |
| `-T, --magic <pcap-magic>` | Pcap magic number/format to store (see `-D` for types) |

### trafgen (generator)

| Parameter | Description |
|-----------|-------------|
| `-i, --in <cfg>` | Input packet configuration file or stdin |
| `-o, --out <dev>` | Output network device or pcap file |
| `-n, --num <count>` | Number of packets to send (default: 0 = infinite) |
| `-t, --gap <time>` | Set approximate interpacket gap (s/ms/us/ns, default: us) |
| `-P, --cpus <uint>` | Number of forks/CPUs to use (default: all CPUs) |
| `-b, --rate <rate>` | Send traffic at specified rate (pps/kpps/Mpps/B/kB/MB/kbit/Mbit/Gbit) |

## Common Commands

```bash
# High-performance packet capture to pcap file
sudo netsniff-ng -i eth0 -o capture.pcap -s

# Capture with BPF filter
sudo netsniff-ng -i eth0 -o capture.pcap -f "tcp port 80 or tcp port 443"

# Capture with time-based rotation (new file every 60 seconds)
sudo netsniff-ng -i eth0 -o /captures/ -T 60

# Filter only host-directed packets
sudo netsniff-ng -i eth0 -o capture.pcap -t host

# Replay a pcap file to a network interface
sudo netsniff-ng -i capture.pcap -o eth0

# Capture N packets
sudo netsniff-ng -i eth0 -o capture.pcap -n 1000

# AS traceroute
sudo astraceroute -i eth0 -d example.com

# Generate custom packets with trafgen
sudo trafgen -i packets.cfg -o eth0 -n 100

# Monitor interface statistics
sudo ifpps -d eth0

# Track live network connections
sudo flowtop
```

## Notes & Tips

1. Requires root privileges for raw socket access.
2. Zero-copy mode via `mmap()` achieves significantly higher capture rates than pcap-based tools — essential for high-throughput network taps.
3. Use `-S` to set the ring buffer size for sustained high-speed capture; default may not be sufficient for 10Gbps+ links.
4. `trafgen` can craft arbitrary packets at line rate — useful for stress testing and protocol fuzzing.
5. `astraceroute` shows autonomous system information along the route path — useful for understanding network topology.

---

## Official References

- [netsniff-ng (Project Site)](http://netsniff-ng.org/)
- [Kali netsniff-ng](https://www.kali.org/tools/netsniff-ng/)
