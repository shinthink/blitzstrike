# sdptool

- **Category**: Wireless / Bluetooth
- **Risk Level**: 🟢 Low

---

## Description

Queries and browses SDP (Service Discovery Protocol) records on Bluetooth devices. After discovering a device with `hcitool scan`, use sdptool to enumerate which services (RFCOMM channels) are available — file transfer, audio, serial port, networking, etc.

## Installation

```bash
apt install bluez
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `browse <BD_ADDR>` | Browse all SDP services on a remote device |
| `search <UUID>` | Search for a specific service UUID on all nearby devices |
| `records <BD_ADDR>` | List all service record handles |
| `add <handle>` | Add a local SDP service record |
| `del <handle>` | Delete a local SDP service record |

## Common Commands

```bash
# Browse all services on a discovered device
sdptool browse AA:BB:CC:DD:EE:FF

# Search for devices with OBEX file transfer service
sdptool search OPUSH

# Search for devices with serial port profile
sdptool search SP

# Search for audio sink (headset/speaker)
sdptool search A2SNK

# Quick scan: just list service names and RFCOMM channels
sdptool browse AA:BB:CC:DD:EE:FF | grep -E "Service Name:|Channel:"
```

## Notes & Tips

1. RFCOMM channel numbers are essential — each service runs on a different RFCOMM channel. For example, OBEX File Transfer might be on channel 9, while headset audio is on channel 3.
2. After identifying an RFCOMM channel, bind it to a local device for interaction: `rfcomm bind 0 <BD_ADDR> <channel>`.
3. Services that are discovered via SDP without authentication can be exploited directly. OBEX (Object Exchange) on insecure devices may allow reading contacts, SMS, and files without pairing.
4. Use `sdptool browse` after `hcitool scan` as the standard Bluetooth reconnaissance workflow.

---

## Official References

- [sdptool Debian man page](https://manpages.debian.org/unstable/bluez/sdptool.1.en.html)
