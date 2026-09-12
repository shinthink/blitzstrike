# sippts

- **Category**: VoIP-ICS / SIP Penetration Testing
- **Risk Level**: 🟡 Medium

---

## Description

Comprehensive SIP (Session Initiation Protocol) penetration testing suite. Provides multiple tools for SIP security assessment: scanning, extension enumeration, authentication testing, call manipulation, and DoS testing. A modern, actively maintained alternative to SIPVicious with broader protocol coverage including WebSocket SIP and RTP/RTCP testing. Written in Python.

Included tools: `sippts scan` (SIP scanner), `sippts exten` (extension enumeration), `sippts rcrack` (remote SIP digest auth cracking), `sippts enumerate` (method enumeration), `sippts flood` (SIP flooding), `sippts invite` (call initiation), `sippts leak` (digest leak exploit), `sippts dump`/`dcrack` (extract + crack digests from PCAP), `sippts sniff` (SIP traffic sniffing), `sippts spoof` (ARP spoofing), `sippts ping` (SIP ping), plus the RTPBleed family (`rtpbleed`/`rtcpbleed`/`rtpbleedflood`/`rtpbleedinject`).

## Installation

```bash
sudo apt install sippts
```

## Parameter Reference

### sippts scan

| Parameter | Description |
|------|------|
| `-i <target>` | Host/IP address/network (e.g., `192.168.0.0/24`) |
| `-r <range>` | Ports to scan (e.g., `5060`, `5070,5080`, `5060-5080`, or `ALL`) |
| `-m <methods>` | Method: `OPTIONS`, `INVITE`, `REGISTER` (default: `OPTIONS`) |
| `-p <proto>` | Transport protocol: `UDP`, `TCP`, `TLS` |
| `-th <n>` | Number of threads |

### sippts exten

| Parameter | Description |
|------|------|
| `-i <target>` | Host/IP address/network (e.g., `192.168.0.0/24`) |
| `-e <range>` | Extension range to enumerate (e.g., `100-999`) |
| `-d <domain>` | Domain or IP address (default: target IP address) |

### sippts rcrack

| Parameter | Description |
|------|------|
| `-i <target>` | Host/IP address/network (e.g., `192.168.0.0/24`) |
| `-e <extension>` | Target extension |
| `-w <wordlist>` | Password wordlist file |

### sippts enumerate

| Parameter | Description |
|------|------|
| `-i <target>` | Host/IP address/network (e.g., `192.168.0.0/24`) |

### sippts invite

| Parameter | Description |
|------|------|
| `-i <target>` | Host/IP address/network (e.g., `192.168.0.0/24`) |
| `-fu <from_user>` | From user (caller) |
| `-tu <to_user>` | To user (default: 100) |

### Additional modules

Full subcommand list (from `sippts -h`, v4.1.2):

| Subcommand | Description |
|------|-------------|
| `astami` | Asterisk AMI pentest module |
| `send` | Send a customized SIP message |
| `wssend` | Send a customized SIP message over WebSocket |
| `leak` | Exploit the SIP Digest Leak vulnerability |
| `ping` | SIP ping |
| `dump` | Dump SIP digest authentications from a PCAP file |
| `dcrack` | SIP digest authentication cracker (offline, against dumped digests) |
| `flood` | Flood a SIP server (DoS) |
| `sniff` | SIP network sniffing |
| `spoof` | ARP spoofing tool |
| `pcapdump` | Extract data from a PCAP file |
| `rtpbleed` | Detect the RTPBleed vulnerability |
| `rtcpbleed` | Detect the RTPBleed vulnerability (RTCP) |
| `rtpbleedflood` | Exploit RTPBleed (flood) |
| `rtpbleedinject` | Exploit RTPBleed (inject audio) |
| `video` | Animated help |

> Each subcommand has its own options — run `sippts <command> -h` (e.g. `sippts scan -h`) for the full per-command parameter list.

## Common Commands

```bash
# Scan for SIP services on a network
sippts scan -i 192.168.1.0/24 -r 5060-5080 -m options -p udp

# Scan using TCP transport
sippts scan -i 192.168.1.0/24 -r 5060 -m options -p tcp

# Enumerate SIP extensions
sippts exten -i 192.168.1.100 -e 100-999

# Enumerate extensions with a specific domain
sippts exten -i 192.168.1.100 -e 100-500 -d example.com

# Enumerate supported SIP methods
sippts enumerate -i 192.168.1.100

# Crack SIP digest authentication
sippts rcrack -i 192.168.1.100 -e 200 -w /usr/share/wordlists/rockyou.txt

# Initiate a test call
sippts invite -i 192.168.1.100 -fu 100 -tu 200

# Test for digest leak vulnerability
sippts leak -i 192.168.1.100

# Sniff SIP traffic
sippts sniff -i 192.168.1.100

# SIP flood test
sippts flood -i 192.168.1.100

# SIP ping
sippts ping -i 192.168.1.100
```

## Notes & Tips

1. SIP scanning and enumeration can trigger intrusion detection systems and account lockouts; confirm VoIP scope and rules of engagement before testing.
2. Use `sippts scan` to discover SIP services before targeted testing with other sippts subcommands -- it identifies live hosts, supported methods, and transport protocols.
3. Extension enumeration (`sippts exten`) response analysis varies by SIP server -- some servers respond identically to valid and invalid extensions, requiring alternative enumeration methods.
4. The `sippts leak` tool exploits a protocol-level vulnerability in SIP digest authentication; document findings carefully for reporting.
5. Use `sippts sniff` to capture SIP traffic for analysis and evidence collection.
6. sippts covers broader protocol surface than SIPVicious, including WebSocket SIP for modern VoIP implementations.

---

## Official References

- [sippts GitHub](https://github.com/Pepelux/sippts)
- [Kali sippts](https://www.kali.org/tools/sippts/)
