# TestDisk

- **Category**: Forensics / Partition Recovery
- **Risk Level**: 🟡 Medium

---

## Description

Powerful partition recovery and repair tool designed to recover lost or deleted partitions, rebuild partition tables, and restore boot sectors. Supports FAT12/16/32, exFAT, NTFS, ext2/3/4, HFS+, and many other file systems. Includes the companion tool PhotoRec for file-level recovery independent of file system metadata. While testdisk primarily uses an interactive TUI, it supports command-line scripting via `/cmd` for automated forensic workflows.

## Installation

```bash
sudo apt install testdisk
```

## Parameter Reference

### testdisk

| Parameter | Description |
|------|------|
| `/log` | Create a testdisk.log file |
| `/debug` | Add debug information to the log |
| `/cmd DEVICE COMMANDS` | Run commands non-interactively (scripting mode) |
| `DEVICE` | Disk or image file path (e.g., /dev/sda, disk.img) |
| `/list` | Display current partition table (non-interactive) |

### PhotoRec

| Parameter | Description |
|------|------|
| `/log` | Create a photorec.log file |
| `/d DIR` | Output directory for recovered files |
| `/cmd DEVICE OPTIONS` | Run PhotoRec non-interactively |

## Common Commands

```bash
# Launch testdisk interactively with logging
sudo testdisk /log

# Launch testdisk on a specific device
sudo testdisk /log /dev/sda

# Analyze a disk image
testdisk /log disk.img

# Scripted: list partitions on a device
sudo testdisk /cmd /dev/sda analyze

# Scripted: search for lost partitions
sudo testdisk /cmd /dev/sda search

# Scripted: advanced search on a disk image
testdisk /cmd disk.img advanced,search

# Debug mode for detailed logging
sudo testdisk /debug /log /dev/sda

# Launch PhotoRec interactively
sudo photorec /log /dev/sda

# PhotoRec: recover files to a specific directory
sudo photorec /d /tmp/recovered/ /log /dev/sda

# PhotoRec scripted: recover from a partition
sudo photorec /cmd /dev/sda1 fileopt,everything,enable,search

# Analyze a forensic image with PhotoRec
photorec /d /tmp/recovered/ /log disk.img
```

## Notes & Tips

1. testdisk is non-destructive in analysis mode -- it reads partition tables and boot sectors without modifying them. Write operations (partition recovery, boot sector repair) require explicit user confirmation in the TUI.
2. Use `/cmd` for scripted, non-interactive workflows suitable for automated forensic pipelines. The TUI mode is more flexible for manual investigation.
3. PhotoRec ignores file system structure entirely, recovering files based on header/footer signatures -- effective even on severely corrupted or reformatted media.
4. Always work on a forensic image (not the original evidence drive) when performing partition recovery or repair operations.
5. The `/log` option creates detailed logs in the current directory -- essential for documenting forensic analysis steps.
6. testdisk can recover partitions from MBR, GPT, Apple Partition Map, and other partition table formats.
7. PhotoRec organizes recovered files into numbered subdirectories (`recup_dir.1/`, `recup_dir.2/`, etc.) and supports over 480 file formats.

---

## Official References

- [TestDisk Official Documentation](https://www.cgsecurity.org/wiki/TestDisk)
- [Kali testdisk](https://www.kali.org/tools/testdisk/)
