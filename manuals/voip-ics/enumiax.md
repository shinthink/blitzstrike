# enumiax

- **Category**: VoIP-ICS / VoIP IAX Assessment
- **Risk Level**: 🟡 Medium

---

## Description

IAX2 username enumeration tool for Asterisk systems. Use it when IAX services are in scope and UDP/4569 is reachable.

## Installation

```bash
apt-get update && apt-get install -y enumiax
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `<target>` | Target host (positional argument) |
| `-d <dict>` | Dictionary attack using this file |
| `-i <count>` | Auto-save interval in operations (default 1000) |
| `-m <min>` | Minimum username length |
| `-M <max>` | Maximum username length |
| `-r <usec>` | Rate-limit delay in microseconds |
| `-s <file>` | Read session state from state file |
| `-v` | Increase verbosity (repeat for additional verbosity) |

## Common Commands

```bash
# Dictionary-based IAX user enumeration
enumiax -d <users.txt> <target>

# Sequential enumeration with username length range
enumiax -m 1 -M 4 <target>

# Dictionary enumeration with verbose output
enumiax -v -d <users.txt> <target>
```

## Notes & Tips

1. IAX enumeration is niche; run only after discovering UDP/4569 or Asterisk indicators.
2. Validate results with service banners, packet captures, or authenticated checks where available.
3. Avoid high-rate enumeration on production PBX systems.

---

## Official References

- [Kali enumiax](https://www.kali.org/tools/enumiax/)

