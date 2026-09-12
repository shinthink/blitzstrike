# airbase-ng

- **Category**: Wireless / Fake AP
- **Risk Level**: 🔴 High

---

## Description

airbase-ng is used to create a software-emulated wireless access point (Soft AP / Rogue AP). It can create open or encrypted networks for man-in-the-middle attack testing, Evil Twin attacks, enterprise credential capture, and similar scenarios. After a client connects, traffic is forwarded through the local machine, enabling traffic analysis and injection.

## Installation

```bash
sudo apt install aircrack-ng
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-e <essid>` | Set the AP SSID name |
| `-a <bssid>` | Set the AP MAC address |
| `-c <channel>` | Set the operating channel |
| `-w <key>` | Set WEP encryption/decryption key |
| `-W 0\|1` | Set WEP flag in beacons (0=don't set, 1=set; default: auto — determined by other flags) |
| `-z <type>` | Set WPA1 cipher type (1=WEP40, 2=TKIP, 3=WRAP, 4=CCMP, 5=WEP104) |
| `-Z <type>` | Set WPA2 cipher type (same values as `-z`; for WPA2 networks; recommend also using `-W 1`) |
| `-X` | Hide SSID |
| `-s` | Force shared key authentication to clients |
| `-S <length>` | Challenge length for shared key auth (16–1480 bytes, default 128) |
| `-f <0|1>` | Disallow (0) or allow (1) specified client MACs (default: allow) |
| `-v` | Verbose output |
| `-P` | Respond to all probe requests |
| `-F <prefix>` | Write captured packets to pcap file with this prefix |
| `-I <ms>` | Beacon frame interval (milliseconds) |
| `-x <pps>` | Packets-per-second limit (default: 100) |

## Common Commands

### Scenario 1: Create an Open AP (Evil Twin)

```bash
# Create an open AP with the same name as the target
sudo airbase-ng -e "FreeWiFi" -c 6 wlan0mon

# After running, an at0 virtual interface is created (client traffic flows through it)
# Configure IP and DHCP to complete the man-in-the-middle setup
# Note: ifconfig argument order is: interface addr netmask mask [up]
sudo ifconfig at0 192.168.99.1 netmask 255.255.255.0 up
```

### Scenario 2: Full Man-in-the-Middle with DHCP

```bash
# 1. Start the Rogue AP
sudo airbase-ng -e "TargetWiFi" -c 6 wlan0mon &

# 2. Configure the at0 interface (wait ~1s for at0 to be created)
sudo ifconfig at0 192.168.99.1 netmask 255.255.255.0 up

# 3. Start DHCP service (requires dnsmasq)
cat > /tmp/dnsmasq.conf << EOF
interface=at0
dhcp-range=192.168.99.2,192.168.99.254,12h
dhcp-option=3,192.168.99.1
dhcp-option=6,192.168.99.1
server=8.8.8.8
log-queries
log-dhcp
EOF
sudo dnsmasq -C /tmp/dnsmasq.conf

# 4. Enable forwarding
sudo sysctl net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### Scenario 3: Respond to All Probe Requests (Honeypot)

```bash
# Respond to all client Probe Requests (responds to any SSID)
sudo airbase-ng -P -c 6 wlan0mon

# Include an SSID name
sudo airbase-ng -P -e "HotSpot" -c 6 wlan0mon
```

## Notes & Tips

1. Creating a Rogue AP and capturing credentials is a serious criminal offense; only authorized testing is permitted
2. In real penetration tests, wifiphisher and hostapd-wpe are generally better alternatives
3. The at0 interface must be manually configured before clients can get network access
4. It is recommended to use Wireshark/tcpdump to monitor traffic on the at0 interface

---

## Official References

- [airbase-ng Documentation](https://www.aircrack-ng.org/doku.php?id=airbase-ng)
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
