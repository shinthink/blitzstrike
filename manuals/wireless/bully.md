# Bully

- **Category**: Wireless / WPS Brute-Force
- **Risk Level**: 🔴 High

---

## Description

An alternative WPS PIN brute-force tool that handles edge cases and AP firmware quirks better than reaver in some environments. Uses a different WPS protocol implementation and manages timeouts and lock states more gracefully. Use bully when reaver fails, stalls, or produces inconsistent results against a target AP. The monitor mode interface is a required positional argument (not a flag): `bully <interface> [options]`.

## Installation

```bash
sudo apt install bully
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-b <bssid>` | MAC address of the target access point |
| `-e <essid>` | Extended SSID for the access point |
| `-c <channel>` | Channel number of AP, or list to hop |
| `-d` / `--pixiewps` | Attempt to use pixiewps |
| `-l <seconds>` / `--lockwait` | Seconds to wait if the AP locks WPS (default: 43) |
| `-i <N>` / `--index` | Starting pin index (7 or 8 digits) (default: Auto) |
| `-p <pin>` | Starting pin number (7 or 8 digits) |
| `-o <file>` / `--outfile` | Output file for messages (default: stdout) |
| `-s <mac>` / `--source` | Source (hardware) MAC address (default: probe) |
| `-v <level>` | Verbosity level 1–4 (default: 3) |
| `-w <path>` / `--workdir` | Location of pin/session files (default: ~/.bully/) |
| `-5` / `--5ghz` | Hop on 5GHz a/n default channel list |
| `-S` / `--sequential` | Sequential pins (do not randomize) |
| `-F` / `--force` | Force continue in spite of warnings |
| `-D` / `--detectlock` | Detect WPS lockouts unreported by AP |
| `-r <N>` / `--retries` | Resend packets N times when not acked (default: 2) |
| `-B` / `--bruteforce` | Bruteforce the WPS pin checksum (last) digit instead of computing it (default: No) |
| `-T` / `--test` | Test mode — do not inject any packets (default: No) |
| `-L` / `--lockignore` | Ignore WPS locks reported by the AP (keep attacking; default: No) |
| `-P` / `--probe` | Use probe requests for a non-beaconing (hidden) AP (default: No) |
| `-Q` / `--wpsinfo` | Use a probe request to gather WPS info from the AP (default: No) |
| `-u` / `--lua` | Lua script file (custom attack logic) |
| `-1 <M,N>` / `--pin1delay` | Delay M seconds every Nth nack at message M5 (default: 0,1) |
| `-2 <M,N>` / `--pin2delay` | Delay M seconds every Nth nack at message M7 (default: 5,1) |

## Common Commands

```bash
# Basic WPS brute force
bully -b AA:BB:CC:DD:EE:FF -e "TargetSSID" -c 6 wlan0mon

# With lock wait delay to reduce AP lockout risk
bully -b AA:BB:CC:DD:EE:FF -e "TargetSSID" -c 6 -l 60 wlan0mon

# Sequential PIN mode (try if random mode fails)
bully -b AA:BB:CC:DD:EE:FF -e "TargetSSID" -c 6 -S wlan0mon

# Verbose output
bully -b AA:BB:CC:DD:EE:FF -e "TargetSSID" -c 6 -v 3 wlan0mon

# Resume from a specific PIN
bully -b AA:BB:CC:DD:EE:FF -e "TargetSSID" -c 6 -p 12345670 wlan0mon
```

## Notes & Tips

1. Use bully when reaver fails or stalls — different implementations handle different AP firmware better.
2. Verify WPS is enabled with `wash -i wlan0mon` before attacking — many modern APs have WPS disabled.
3. Use `-l` (lockwait) to add delays between attempts to avoid AP WPS lockout — some APs lock after 3–5 consecutive failures.
4. A full WPS PIN brute-force takes 4–10 hours — run in a persistent session (tmux or screen).
5. Some APs implement permanent WPS lockout after repeated failures — back off immediately if you see lockout responses.

---

## Official References

- [bully (GitHub)](https://github.com/kimocoder/bully)
- [Kali bully](https://www.kali.org/tools/bully/)
