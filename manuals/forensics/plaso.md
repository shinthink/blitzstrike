# plaso

- **Category**: Forensics / Timeline Analysis
- **Risk Level**: 🟢 Low

---

## Description

Plaso (Plaso Langar Að Safna Öllu — "plaso gathers everything") is a super-timeline generation engine. It extracts timestamped events from disk images, individual files, log files, registry hives, and other forensic artifacts, then merges them into a single chronological timeline.

The Kali package provides the following binaries (note: **not** `log2timeline.py` or `psort.py`):
- **`plaso-log2timeline`** — Event extraction
- **`plaso-psort`** — Sorting, filtering, and output
- **`plaso-pinfo`** — Storage file info
- **`plaso-psteal`** — Combined extraction + output (convenience wrapper)
- **`plaso-image_export`** — Export files from storage media

Essential for incident response and forensic investigations.

## Installation

```bash
sudo apt install plaso
```

## Parameter Reference

### plaso-log2timeline

| Parameter | Description |
|-----------|-------------|
| `--storage-file <file>` | Output plaso storage file |
| `--parsers <list>` | Comma-separated parser names or presets |
| `--hashers <list>` | Hash algorithms to compute (md5, sha256) |
| `--status_view <type>` | Status display (linear, window, none) |
| `--workers <n>` | Number of extraction workers |
| `--single-process` | Run in single process (for debugging) |
| `--yara_rules <file>` | YARA rules file for matching |
| `<source>` | Disk image, directory, or file to process |

### plaso-psort

| Parameter | Description |
|-----------|-------------|
| `-o <format>` | Output format (dynamic, l2tcsv, json_line, opensearch, etc.) |
| `-w <file>` | Output file path |
| `--slice <datetime>` | Time slice center point |
| `--slice_size <minutes>` | Time slice window size |
| `-q` | Quiet mode |

### plaso-pinfo

| Parameter | Description |
|-----------|-------------|
| `--sections <list>` | Sections to display (events, parsers, warnings) |
| `<storage_file>` | Plaso storage file to inspect |

## Common Commands

### Scenario 1: Process a disk image

```bash
# Extract all events from a disk image into a plaso storage file
plaso-log2timeline --storage-file /tmp/timeline.plaso /evidence/disk.E01

# Process with specific parsers only
plaso-log2timeline --storage-file /tmp/timeline.plaso \
  --parsers "winevtx,winreg,prefetch,mft" /evidence/disk.E01
```

### Scenario 2: Generate CSV timeline

```bash
# Convert plaso storage to CSV
plaso-psort -o l2tcsv -w /tmp/timeline.csv /tmp/timeline.plaso

# Generate dynamic (customizable columns) output
plaso-psort -o dynamic -w /tmp/timeline.txt /tmp/timeline.plaso
```

### Scenario 3: Time-slice analysis

```bash
# Extract events around a specific incident time (30 min window)
plaso-psort -o l2tcsv -w /tmp/incident_window.csv \
  --slice "2024-06-15T14:30:00" --slice_size 30 /tmp/timeline.plaso
```

### Scenario 4: Process log files

```bash
# Process a directory of log files
plaso-log2timeline --storage-file /tmp/logs.plaso /evidence/var_log/

# Process with hash computation
plaso-log2timeline --storage-file /tmp/logs.plaso --hashers md5,sha256 /evidence/
```

### Scenario 5: Inspect storage file

```bash
# Display storage file summary
plaso-pinfo /tmp/timeline.plaso

# Show parser statistics
plaso-pinfo --sections parsers /tmp/timeline.plaso
```

## Notes & Tips

1. Processing a full disk image can take hours — use `--parsers` to focus on relevant artifact types for faster results
2. The `l2tcsv` output format is compatible with most timeline analysis tools and spreadsheet applications
3. Use `--slice` in psort to zoom in on specific incident windows instead of processing the entire timeline
4. Plaso supports raw (dd), EWF (E01), QCOW2, VHD, and VMDK image formats
5. Combine with Sleuth Kit's `fls -m` and YARA rules for comprehensive forensic analysis

---

## Official References

- [plaso (GitHub)](https://github.com/log2timeline/plaso)
- [plaso Documentation](https://plaso.readthedocs.io/)
- [plaso — Kali Tools](https://www.kali.org/tools/plaso/)
