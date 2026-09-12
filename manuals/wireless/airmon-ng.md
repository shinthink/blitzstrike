# airmon-ng

- **Category**: Wireless / Interface Management
- **Risk Level**: 🟡 Medium

---

## Description

airmon-ng is a tool in the aircrack-ng suite for managing wireless adapter operating modes. Its core function is to switch the wireless interface into **Monitor Mode**, enabling the adapter to capture all surrounding 802.11 wireless frames — not just traffic associated with the local machine. It can also identify and kill processes that may interfere with capturing (such as NetworkManager and wpa_supplicant).

## Installation

```bash
sudo apt install aircrack-ng
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `check` | Check for processes that may interfere with monitoring |
| `check kill` | Check and forcefully terminate interfering processes |
| `start <interface>` | Start monitor mode on the specified interface |
| `start <interface> <channel>` | Start monitor mode and lock to the specified channel |
| `stop <interface>` | Stop monitor mode and restore managed mode |
| `<interface>` | Wireless interface name (e.g., wlan0, wlan1) |

## Common Commands

### Scenario 1: Start Monitor Mode

```bash
# View wireless interfaces
iwconfig

# Check for interfering processes
sudo airmon-ng check

# Kill interfering processes (recommended before monitoring)
sudo airmon-ng check kill

# Switch wlan0 to monitor mode (creates wlan0mon interface)
sudo airmon-ng start wlan0

iwconfig wlan0mon
```

### Scenario 2: Lock to a Specific Channel

```bash
# Start monitor mode and lock to channel 6 (2.4GHz)
sudo airmon-ng start wlan0 6

# Start monitor mode and lock to channel 36 (5GHz)
sudo airmon-ng start wlan0 36
```

### Scenario 3: Stop Monitor Mode

```bash
# Stop monitoring, restore normal mode
sudo airmon-ng stop wlan0mon

# Restart NetworkManager (may need to do this manually)
sudo systemctl restart NetworkManager
```

### Scenario 4: Full Workflow

```bash
# 1. Check and kill interfering processes
sudo airmon-ng check kill

# 2. Start monitor mode
sudo airmon-ng start wlan0

# 3. Use airodump-ng to scan (next step)
sudo airodump-ng wlan0mon

# 4. Restore when done
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```

## Notes & Tips

1. Running `check kill` will disconnect the current Wi-Fi connection — be mindful of network dependencies during testing
2. Some adapter drivers do not support monitor mode (e.g., certain Realtek chipsets); an external USB adapter may be required
3. Monitor mode interface naming convention: `wlan0` → `wlan0mon`, sometimes `mon0`
4. 5GHz monitoring requires both adapter and driver support
5. When using a VM, a USB wireless adapter with passthrough is required; built-in adapters typically cannot monitor
6. Always restore to managed mode after testing, or normal network connectivity will be unavailable

---

## Official References

- [airmon-ng Documentation](https://www.aircrack-ng.org/doku.php?id=airmon-ng)
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
