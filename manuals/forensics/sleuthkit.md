# The Sleuth Kit

- **Category**: Forensics / Disk Forensics
- **Risk Level**: 🟢 Low

---

## Description

The Sleuth Kit (TSK) is a collection of command-line digital forensics tools for analyzing disk images and file systems. It supports NTFS, FAT, EXT2/3/4, HFS+, UFS, and other file systems. Key tools include `mmls` (partition layout), `fls` (file listing including deleted files), `icat` (file extraction by inode), `fsstat` (file system details), `tsk_recover` (bulk file recovery), and `img_stat` (image info). The foundation for disk forensics analysis.

## Installation

```bash
sudo apt install sleuthkit
```

## Parameter Reference

### Volume System Tools

| Parameter | Description |
|-----------|-------------|
| `mmls <image>` | Display partition layout |
| `mmstat <image>` | Display volume system type |
| `mmcat <image> <vol>` | Extract partition contents |

### File System Tools

| Parameter | Description |
|-----------|-------------|
| `fls -o <offset> <image>` | Sector offset into image file |
| `fls -r` | Recurse on directory entries |
| `fls -l` | Long listing (like ls -l) with file details |
| `fls -p` | Display full path for each entry |
| `fls -d` | Show deleted entries only |
| `fls -D` | Show directories only |
| `fls -F` | Show files only |
| `fls -u` | Show undeleted entries only |
| `fls -m <mount>` | Display output in mactime input format |
| `fls -f <fstype>` | Specify filesystem type |
| `fls -z <zone>` | Specify timezone |
| `icat -o <offset> <image> <inode>` | Sector offset into image file |
| `fsstat -o <offset> <image>` | Sector offset into image file |
| `ffind -o <offset> <image> <inode>` | Sector offset into image file |
| `blkcat -o <offset> <image> <block>` | Sector offset into image file |

### Recovery Tools

| Parameter | Description |
|-----------|-------------|
| `tsk_recover -o <offset> <image> <outdir>` | Sector offset into image file |
| `tsk_recover -e` | Recover all files (not just deleted) |
| `sorter -o <offset> <image> <outdir>` | Sector offset into image file |

### Image Tools

| Parameter | Description |
|-----------|-------------|
| `img_stat <image>` | Display image file details |
| `img_cat <image>` | Output image contents to stdout |

## Common Commands

### Scenario 1: Partition analysis

```bash
# List partition layout
mmls disk_image.dd

# Output: start/end sectors, size, description for each partition
# Note the offset value for the target partition
```

### Scenario 2: File listing and deleted file recovery

```bash
# List all files recursively (offset from mmls output)
fls -r -o 2048 disk_image.dd

# List deleted files only
fls -r -d -o 2048 disk_image.dd

# Extract a specific file by inode number
icat -o 2048 disk_image.dd 12345 > /tmp/recovered_file.doc
```

### Scenario 3: Timeline generation

```bash
# Generate mactime body file
fls -r -m "/" -o 2048 disk_image.dd > /tmp/bodyfile.txt

# Convert body file to timeline
mactime -b /tmp/bodyfile.txt -d > /tmp/timeline.csv

# Filter timeline by date range
mactime -b /tmp/bodyfile.txt -d 2024-01-01..2024-12-31 > /tmp/timeline_2024.csv
```

### Scenario 4: Bulk file recovery

```bash
# Recover all deleted files from a partition
tsk_recover -o 2048 disk_image.dd /tmp/recovered/

# Recover all files (including non-deleted)
tsk_recover -e -o 2048 disk_image.dd /tmp/all_files/
```

### Scenario 5: File system analysis

```bash
# Display file system details (type, block size, volume name)
fsstat -o 2048 disk_image.dd

# Find the filename for a known inode
ffind -o 2048 disk_image.dd 12345

# Display raw block content (for manual analysis)
blkcat -o 2048 disk_image.dd 1000 | xxd | head -20
```

## Notes & Tips

1. The `-o` offset parameter is in sectors (typically 512 bytes each); get the correct value from `mmls` output
2. Deleted file inodes appear with `*` prefix in `fls` output — extract them with `icat` before they are overwritten
3. Combine `fls -m` timeline output with `plaso` for comprehensive super-timeline analysis
4. TSK supports raw (dd), EWF (E01), and AFF image formats
5. Use `tsk_recover` for bulk recovery; use `icat` for targeted individual file extraction

---

## Official References

- [The Sleuth Kit](https://www.sleuthkit.org/)
- [sleuthkit (GitHub)](https://github.com/sleuthkit/sleuthkit)
- [sleuthkit — Kali Tools](https://www.kali.org/tools/sleuthkit/)
