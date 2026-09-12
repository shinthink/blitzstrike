# RegRipper

- **Category**: Forensics / Windows Registry Analysis
- **Risk Level**: 🟢 Low

---

## Description

Extracts and parses forensic data from Windows Registry hive files using a plugin-based architecture. Plugins target specific artifacts: user accounts, installed software, USB device history, MRU lists, network connections, autostart programs, file associations, and more. Essential for Windows forensic investigations where Registry analysis reveals user activity, system configuration, and evidence of compromise. Written in Perl with an extensive plugin library (RegRipper 3.0).

## Installation

```bash
sudo apt install regripper
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-r HIVE` | Path to the Registry hive file |
| `-p PLUGIN` | Run a specific plugin |
| `-f PROFILE` | Run all plugins for a profile: sam, ntuser, system, software, usrclass, all |
| `-l` | List all available plugins |
| `-a` | Auto-run all applicable (hive-specific) plugins for the hive |
| `-d` | Check to see if the hive is dirty (has unprocessed transaction logs) |
| `-g` | Guess the hive file type |
| `-aT` | Automatically run hive-specific TLN (timeline) plugins |
| `-c` | Output the plugin list in CSV format (use with `-l`) |
| `-s SYSTEMNAME` | System name (TLN support) |
| `-u USERNAME` | User name (TLN support) |
| `-uP` | Update default profiles |

## Common Commands

```bash
# List all available plugins
regripper -l

# Run all plugins for an NTUSER.DAT hive
regripper -r /mnt/evidence/Users/admin/NTUSER.DAT -f ntuser

# Run all plugins for the SAM hive
regripper -r /mnt/evidence/Windows/System32/config/SAM -f sam

# Run all plugins for the SYSTEM hive
regripper -r /mnt/evidence/Windows/System32/config/SYSTEM -f system

# Run all plugins for the SOFTWARE hive
regripper -r /mnt/evidence/Windows/System32/config/SOFTWARE -f software

# Run all plugins for the UsrClass.dat hive
regripper -r "/mnt/evidence/Users/admin/AppData/Local/Microsoft/Windows/UsrClass.dat" -f usrclass

# Run a specific plugin (e.g., USB device history)
regripper -r /mnt/evidence/Windows/System32/config/SYSTEM -p usbstor

# Run a specific plugin for autostart entries
regripper -r /mnt/evidence/Users/admin/NTUSER.DAT -p run

# Auto-run all applicable plugins
regripper -r /mnt/evidence/Windows/System32/config/SOFTWARE -a

# Save output to a file for reporting
regripper -r /mnt/evidence/Windows/System32/config/SYSTEM -f system > system_analysis.txt

# Run recently-used documents plugin
regripper -r /mnt/evidence/Users/admin/NTUSER.DAT -p recentdocs
```

## Notes & Tips

1. Registry hive files are typically found at `C:\Windows\System32\config\` (SAM, SYSTEM, SOFTWARE, SECURITY) and `C:\Users\<user>\NTUSER.DAT` (per-user).
2. Use the `-f` profile option to batch-run all relevant plugins for a hive type -- this is more efficient than running plugins individually.
3. The `UsrClass.dat` hive (under `AppData\Local\Microsoft\Windows\`) contains shellbag data that records folder access history.
4. Common forensically significant plugins: `usbstor` (USB devices), `run` (autostart), `recentdocs` (recent files), `userassist` (program execution), `networklist` (Wi-Fi history).
5. Plugin output includes timestamps when available -- correlate these with timeline analysis from other forensic tools.
6. Mount the evidence disk read-only before extracting hive files to preserve forensic integrity.
7. For locked hives on a live Windows system, use volume shadow copies or forensic imaging to access the files.

---

## Official References

- [RegRipper 3.0 (GitHub)](https://github.com/keydet89/RegRipper3.0)
- [Kali regripper](https://www.kali.org/tools/regripper/)
