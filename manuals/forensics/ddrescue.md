# ddrescue

- **Category**: Forensics / Data Recovery
- **Risk Level**: 🟡 Medium

---

## Description

GNU ddrescue is a data recovery tool for copying data from damaged media (failing hard drives, scratched CDs/DVDs, corrupted flash drives). Unlike dd, it does not truncate the output file on errors, uses a mapfile to track recovery progress, and performs multiple passes with increasingly aggressive retry strategies. Preserves all recovered data between runs. Essential for forensic imaging of damaged evidence drives where standard imaging tools fail.

## Installation

```bash
sudo apt install gddrescue
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `infile` | Input device or file (positional, first argument) |
| `outfile` | Output file or device (positional, second argument) |
| `mapfile` | Recovery progress map (positional, third argument) |
| `-f` | Force; allow overwriting an existing output file |
| `-n` | No-scrape; skip the scraping phase on first pass for speed |
| `-r <n>` | Maximum retry passes for bad sectors (default: 0) |
| `-d` | Use direct I/O (bypass kernel cache) for input |
| `-R` | Reverse direction; read from end to beginning |
| `-i <pos>` | Starting input position (e.g., `1M`, `500K`) |
| `-o <pos>` | Starting output position |
| `-s <size>` | Maximum bytes to copy from input |
| `-c <n>` | Cluster size (sectors per read attempt) |
| `-b <size>` | Sector size in bytes (default: 512) |
| `-v` | Verbose; increase output detail |
| `--log-events <file>` | Log significant events to a file |

## Common Commands

```bash
# Basic recovery from a failing drive
sudo ddrescue /dev/sdb /mnt/output/disk.img /mnt/output/disk.map

# First pass: fast copy, skip bad sectors (no-scrape)
sudo ddrescue -n /dev/sdb /mnt/output/disk.img /mnt/output/disk.map

# Second pass: retry bad sectors from first pass
sudo ddrescue -r 3 /dev/sdb /mnt/output/disk.img /mnt/output/disk.map

# Reverse direction recovery (useful when drive fails at a specific area)
sudo ddrescue -R -r 3 /dev/sdb /mnt/output/disk.img /mnt/output/disk.map

# Use direct I/O to bypass kernel caching
sudo ddrescue -d -n /dev/sdb /mnt/output/disk.img /mnt/output/disk.map

# Recovery with verbose output and event logging
sudo ddrescue -v --log-events /mnt/output/events.log /dev/sdb /mnt/output/disk.img /mnt/output/disk.map

# Copy only first 1GB of a device
sudo ddrescue -s 1G /dev/sdb /mnt/output/partial.img /mnt/output/partial.map

# Set sector size for non-standard media (e.g., 4K sectors)
sudo ddrescue -b 4096 /dev/sdb /mnt/output/disk.img /mnt/output/disk.map

# Force overwrite an existing output file
sudo ddrescue -f /dev/sdb /mnt/output/disk.img /mnt/output/disk.map
```

## Notes & Tips

1. Always use a mapfile (third positional argument) -- it tracks which sectors have been copied, allowing recovery to resume after interruption without re-reading successful sectors.
2. Use a two-pass strategy: first pass with `-n` (no-scrape) to quickly recover all good data, then a second pass with `-r 3` to retry bad sectors.
3. Never write output to the same device being recovered -- use a separate, healthy drive or network storage.
4. The package name is `gddrescue` (GNU ddrescue), not `ddrescue` which is a different, older tool. The command is still `ddrescue`.
5. Use `-d` (direct I/O) for failing drives to avoid kernel read-ahead triggering additional reads on bad areas.
6. The `-R` (reverse) flag can recover data from drives that fail progressively from one end -- alternate forward and reverse passes.
7. Monitor the mapfile to track recovery progress: it shows rescued, non-tried, non-trimmed, non-scraped, bad-sector, and failed counts.

---

## Official References

- [GNU ddrescue (Official)](https://www.gnu.org/software/ddrescue/)
