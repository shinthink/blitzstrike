# chntpw

- **Category**: Password Attacks / Offline Windows Password Recovery
- **Risk Level**: 🟡 Medium

---

## Description

An offline utility for viewing and changing user passwords in Windows NT/2000/XP through Windows 8.1 SAM database files. Works by directly editing the Windows registry files — no Windows login required. Also includes an interactive registry editor and hex editor. Used in post-exploitation and forensics scenarios to recover or reset Windows credentials when physical or filesystem access is available.

## Installation

```bash
sudo apt install chntpw
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<SAM file>` | Path to the Windows SAM file |
| `-u <username>` | Username or RID (0x3e9 for example) to interactively edit |
| `-l` | List all users in the SAM database |
| `-i` | Interactive menu system |
| `-e` | Registry editor (limited capabilities, includes write support) |
| `-d` | Enter buffer debugger (hex editor mode) |
| `<system file>` | SYSTEM hive file (needed for full decryption with syskey) |

## Common Commands

```bash
# Mount the Windows partition first
mount /dev/sda2 /mnt/windows

# List all users in the SAM database
chntpw -l /mnt/windows/Windows/System32/config/SAM

# Reset Administrator password (interactive)
chntpw /mnt/windows/Windows/System32/config/SAM

# Reset specific user password non-interactively
chntpw -u "jdoe" /mnt/windows/Windows/System32/config/SAM

# With SYSTEM hive (required if syskey is enabled)
chntpw /mnt/windows/Windows/System32/config/SAM /mnt/windows/Windows/System32/config/SYSTEM

# Interactive user selection menu
chntpw -i /mnt/windows/Windows/System32/config/SAM

# From Kali live boot (common use case)
# Boot Kali from USB, mount Windows drive, run chntpw
```

## Notes & Tips

1. Requires physical access or filesystem access (e.g., via a shared volume or forensic image) — cannot work remotely.
2. In a penetration test, if you have filesystem access to a Windows system (via LFI, backup, or physical access), chntpw can reset or blank local account passwords in the SAM file.
3. The SAM file is locked while Windows is running — boot from Kali live media or access via another OS.
4. Modern Windows with BitLocker will encrypt the SAM file — chntpw cannot access BitLocker-encrypted volumes without the key.
5. For live Windows systems with shell access, use impacket-secretsdump or lsassy instead — chntpw requires offline file access.

---

## Official References

- [chntpw man page](https://manpages.debian.org/chntpw)
- [Kali chntpw](https://www.kali.org/tools/chntpw/)
