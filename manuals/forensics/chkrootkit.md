# chkrootkit

- **Category**: Forensics / Rootkit Detection
- **Risk Level**: 🟢 Low

---

## Description

Locally checks for signs of rootkits on Unix/Linux systems. Examines system binaries for known rootkit modifications, checks kernel modules, network interfaces (promiscuous mode), log files, and process listings for signs of compromise. Tests for over 70 known rootkit signatures including LKM trojans, worm indicators, and suspicious file anomalies. Runs entirely from the command line with no persistent agent.

## Installation

```bash
sudo apt install chkrootkit
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-q` | Quiet mode; show only infected results |
| `-x` | Expert mode; display all test data for manual inspection |
| `-r DIR` | Use DIR as the alternate root directory for checks |
| `-p <dir1:dir2:...>` | Path for external commands used by chkrootkit (colon-separated) |
| `-l` | Show available tests and exit |
| `-n` | Skip NFS mount points |
| `-e '<file1 file2>'` | Exclude files/dirs from results (space-separated, quoted) |

## Common Commands

```bash
# Run all default checks
sudo chkrootkit

# Quiet mode (show only infections found)
sudo chkrootkit -q

# Expert mode (verbose output for manual analysis)
sudo chkrootkit -x

# List all available tests
chkrootkit -l

# Check a mounted forensic image (alternate root)
sudo chkrootkit -r /mnt/evidence

# Use trusted binaries from a known-good path
sudo chkrootkit -p /mnt/trusted_bin

# Skip NFS-mounted directories
sudo chkrootkit -n

# Exclude specific directories
sudo chkrootkit -e "/tmp /var/tmp"

# Run a specific test only
sudo chkrootkit chkutmp

# Save results to a log file
sudo chkrootkit -q > /tmp/chkrootkit_report.txt 2>&1
```

## Notes & Tips

1. Run chkrootkit with `sudo` or as root -- many checks require privileged access to examine system binaries and kernel modules.
2. For forensic analysis, use `-r` to check a mounted disk image instead of the live system, avoiding potential interference from an active rootkit.
3. Use `-p` to point to trusted, known-good binaries (e.g., from a clean USB) when the local system may be compromised.
4. False positives are common, especially on systems with custom kernels or non-standard configurations. Verify findings manually before concluding compromise.
5. Combine with `rkhunter` for broader rootkit detection coverage -- each tool detects different signatures.
6. Schedule periodic checks via cron and compare results over time to detect new infections.
7. The `-x` (expert) mode outputs raw test data useful for scripted post-processing and automated alerting.

---

## Official References

- [chkrootkit Official Site](http://www.chkrootkit.org/)
- [Kali chkrootkit](https://www.kali.org/tools/chkrootkit/)
