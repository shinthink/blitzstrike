# Scapy

- **Category**: Sniffing & Spoofing / Packet Crafting
- **Risk Level**: 🟡 Medium

---

## Description

A Python-based interactive packet manipulation framework. Allows crafting, sending, sniffing, and dissecting network packets at any protocol layer — IP, TCP, UDP, ICMP, DNS, ARP, DHCP, and more. More flexible than hping3 for complex scenarios: building custom protocols, fuzzing network stacks, creating proof-of-concept exploits, and ARP scanning. Used both interactively and as a Python library in automated scripts.

## Installation

```bash
sudo apt install python3-scapy
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `scapy` | Launch interactive Python shell |
| `send(<pkt>)` | Send Layer-3 packet (no response capture) |
| `sendp(<pkt>)` | Send Layer-2 packet (Ethernet frame) |
| `sr(<pkt>)` | Send and receive multiple replies |
| `sr1(<pkt>)` | Send and receive one reply |
| `srp(<pkt>)` | Send/receive at Layer-2 |
| `sniff(...)` | Capture packets live |
| `rdpcap(<file>)` | Read pcap file |
| `wrpcap(<file>, <pkts>)` | Write packets to pcap file |

## Common Commands

```bash
# Launch scapy interactive shell
scapy

# Send a TCP SYN to port 80
python3 -c "from scapy.all import *; send(IP(dst='192.168.1.10')/TCP(dport=80, flags='S'))"

# Ping and capture reply
python3 -c "
from scapy.all import *
r = sr1(IP(dst='192.168.1.10')/ICMP(), timeout=2)
r.show() if r else print('No reply')
"

# TCP SYN scan a list of ports
python3 -c "
from scapy.all import *
ans, _ = sr(IP(dst='192.168.1.10')/TCP(dport=[22,80,443,8080], flags='S'), timeout=2)
for s, r in ans:
    print(f'Port {r[TCP].sport} open')
"

# ARP scan local subnet (host discovery)
python3 -c "
from scapy.all import *
ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst='192.168.1.0/24'), timeout=2)
for s, r in ans:
    print(r.psrc, r.hwsrc)
"

# DNS query via scapy
python3 -c "
from scapy.all import *
r = sr1(IP(dst='8.8.8.8')/UDP()/DNS(rd=1, qd=DNSQR(qname='example.com')), timeout=2)
r[DNS].an.show()
"

# Sniff HTTP traffic live
python3 -c "from scapy.all import *; sniff(iface='eth0', filter='tcp port 80', prn=lambda x: x.show(), count=10)"

# Read pcap and show TCP packets
python3 -c "from scapy.all import *; [p.show() for p in rdpcap('capture.pcap') if p.haslayer(TCP)]"
```

## Notes & Tips

1. Scapy requires root/sudo for raw socket operations (Layer-2 and Layer-3 packet injection).
2. Use `sr1()` for single-packet request-response; `sr()` for multiple; `sniff()` for passive capture.
3. `sniff(filter='...')` accepts standard BPF syntax — same as tcpdump filters.
4. Scapy is ideal for PoC development and protocol fuzzing where hping3's fixed modes are insufficient.
5. For high-volume scanning, nmap and masscan are orders of magnitude faster — use scapy for custom protocol logic.

---

## Official References

- [Scapy (GitHub)](https://github.com/secdev/scapy)
- [Kali scapy](https://www.kali.org/tools/scapy/)
