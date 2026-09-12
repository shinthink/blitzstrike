# scalpel

- **Category**: Forensics / File Carving
- **Risk Level**: 🟢 Low

---

## Description

High-performance file carving tool, originally based on Foremost. Recovers files from disk images, raw partitions, or any block device based on file header and footer signatures defined in a configuration file. Independent of file system metadata, enabling recovery from corrupted or reformatted media. Supports dozens of file types and allows custom signature definitions.

## Installation

```bash
sudo apt install scalpel
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-c FILE` | Choose configuration file |
| `-o DIR` | Set output directory for carved files |
| `-b` | Carve files even if defined footers aren't discovered within maximum carve size |
| `-i FILE` | Read names of disk images from specified file |
| `-r` | Find only first of overlapping headers/footers (foremost compat mode) |
| `-V` | Display copyright information and exit |
| `-n` | Don't add extensions to extracted files |
| `-q` | Carve only when header is cluster-aligned |
| `-p` | Perform image file preview; audit log indicates which files would be carved |

## Common Commands

```bash
# Edit configuration file to enable desired file types (uncomment relevant lines)
sudo nano /etc/scalpel/scalpel.conf

# Carve files from a disk image
scalpel -c /etc/scalpel/scalpel.conf -o /tmp/carved/ disk.img

# Carve files from a raw device
sudo scalpel -c /etc/scalpel/scalpel.conf -o /tmp/carved/ /dev/sdb

# Preview what files would be recovered without extracting
scalpel -p -c /etc/scalpel/scalpel.conf -o /tmp/preview/ disk.img

# Report only (no extraction)
scalpel -n -c /etc/scalpel/scalpel.conf -o /tmp/report/ disk.img

# Carve with header-only matching (no footer required)
scalpel -r -c /etc/scalpel/scalpel.conf -o /tmp/carved/ disk.img

# Use a custom configuration file
scalpel -c custom.conf -o /tmp/carved/ disk.img
```

## Notes & Tips

1. The configuration file (`/etc/scalpel/scalpel.conf`) has all file types commented out by default -- uncomment the lines for the types you want to recover before running.
2. The output directory must not exist before running scalpel; it creates the directory automatically.
3. scalpel is non-destructive -- it reads input files/devices in read-only mode and never modifies the source.
4. For large disk images, use `-p` (preview) first to estimate recovery results before performing full extraction.
5. Custom signatures can be added to the configuration file using the format: `type  case_sensitive  max_size  header  [footer]`.
6. scalpel is generally faster than `foremost` for the same task due to optimized I/O and memory management.
7. Review the `audit.txt` file in the output directory to see a summary of all carved files and their offsets.

---

## Official References

- [Kali scalpel](https://www.kali.org/tools/scalpel/)
- [scalpel (GitHub - Sleuth Kit)](https://github.com/sleuthkit/scalpel)
