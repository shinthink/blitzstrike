# Proxmark3

- **Category**: RFID/NFC / RFID and NFC
- **Risk Level**: 🔴 Critical

---

## Description

CLI client for Proxmark3 RFID/NFC hardware. Supports LF/HF card identification, reads, key checks, dumps, simulation, and cloning workflows. Use only with explicit physical-access authorization and the required hardware.

## Installation

```bash
# Install from Kali repos
sudo apt install proxmark3

# Verify
proxmark3 --help
```

## Parameter Reference

### Client Options

| Parameter | Description |
|------|------|
| `-p/--port <port>` | Serial port to connect to |
| `-c/--command <command>` | Execute one Proxmark3 command (or several separated by ';') |
| `-l/--lua <lua_script_file>` | Execute Lua script |
| `-y/--py <python_script_file>` | Execute Python script |
| `-s/--script-file <cmd_script_file>` | Script file with one Proxmark3 command per line |
| `-w/--wait` | 20sec waiting for the serial port to appear in the OS |
| `-f/--flush` | Output will be flushed after every print |
| `-b/--baud` | Serial port speed (only needed for physical UART, not USB-CDC or BT) |
| `-i/--interactive` | Enter interactive mode after executing the script or command |
| `-d/--debug <0|1|2>` | Set debug mode |
| `-v/--version` | Print client version |
| `--incognito` | Do not use history, prefs file nor log files |
| `--ncpu <num_cores>` | Override number of CPU cores |

### Flasher Options

| Parameter | Description |
|------|------|
| `--flash` | Flash Proxmark3, requires at least one --image |
| `--unlock-bootloader` | Enable flashing of bootloader area (DANGEROUS) |
| `--force` | Enable flashing even if firmware seems to not match client version |
| `--image <imagefile>` | Image to flash (can be specified several times) |
| `--reboot-to-bootloader` | Reboot Proxmark3 into bootloader mode |

### Common Interactive Commands

| Command | Description |
|------|------|
| `auto` | Identify nearby card/tag |
| `lf search` | Search low-frequency tags |
| `hf search` | Search high-frequency tags |
| `hf mf chk` | Check MIFARE Classic keys |
| `hf mf dump` | Dump MIFARE Classic data after key recovery |
| `hf 14a reader` | Read ISO14443A tag information |
| `hf mf darkside` | Darkside attack to recover first unknown key (MIFARE Classic) |
| `hf mf nested` | Nested attack using a known key to recover other keys |
| `hf mf sim` | Simulate a MIFARE Classic card |
| `hf mf restore` | Restore a dump to a MIFARE Classic card |
| `lf em 410x clone` | Clone EM4100 LF card to a T5577 |

## Common Commands

```bash
# Auto-identify card (requires device port)
proxmark3 /dev/ttyACM0 -c "auto"

# High-frequency search
proxmark3 /dev/ttyACM0 -c "hf search"

# MIFARE Classic key check
proxmark3 /dev/ttyACM0 -c "hf mf chk --1k"

# Read ISO14443A tag information
proxmark3 /dev/ttyACM0 -c "hf 14a reader"

# Execute a Lua script
proxmark3 /dev/ttyACM0 -l hf_read

# Execute commands from a script file
proxmark3 /dev/ttyACM0 -s mycmds.txt

# Run in offline mode (no hardware)
proxmark3
```

## Notes & Tips

1. Cloning, simulation, writing, and key attacks require explicit approval beyond basic identification.
2. Preserve card UID, ATQA/SAK, reader model, command log, and dump hashes.
3. Proxmark3 command syntax varies by client branch; verify with `help` on the installed client.

---

## Official References

- [Proxmark3 GitHub](https://github.com/RfidResearchGroup/proxmark3)
- [Proxmark3 command reference](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/commands.md)
