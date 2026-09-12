# rkhunter

- **Category**: Forensics / Rootkit Detection
- **Risk Level**: 🟢 Low

---

## Description

Rootkit Hunter scans for rootkits, backdoors, and local exploits on Unix/Linux systems. Checks system binaries for known rootkit modifications, compares file hashes against known good values, checks for hidden files and processes, tests network interfaces for promiscuous mode, and examines system startup files. Uses a signature-based approach combined with heuristic analysis. Complements chkrootkit with different detection methods and a broader signature database.

## Installation

```bash
sudo apt install rkhunter
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `--check` | Check the local system |
| `--skip-keypress` | Don't wait for a keypress after each test |
| `--report-warnings-only` | Show only warning messages |
| `--enable <tests>` | Enable specific tests (default is to enable all tests) |
| `--disable <tests>` | Disable specific tests (default is to disable no tests) |
| `--list` | List available tests, languages, rootkits, and properties |
| `--update` | Check for updates to database files |
| `--propupd` | Update the entire file properties database |
| `--versioncheck` | Check for the latest version of rkhunter |
| `--logfile <file>` | Write to a logfile (default is /var/log/rkhunter.log) |
| `--hash <algorithm>` | Use the specified file hash function (MD5, SHA1, SHA256, etc.; default: SHA256) |
| `--config-check` | Check the configuration file(s), then exit |
| `--append-log` | Append to the logfile, do not overwrite |
| `--nocolors` | Use black and white output |
| `--display-logfile` | Display the logfile at the end |
| `-q` | Quiet mode; suppress all output except errors |
| `--cronjob` | Run as a cron job (implies -c, --sk, and --nocolors options) |

## Common Commands

```bash
# Run all default checks
sudo rkhunter --check

# Run checks non-interactively (skip keypresses)
sudo rkhunter --check --skip-keypress

# Show only warnings (suppress OK results)
sudo rkhunter --check --report-warnings-only --skip-keypress

# Update signature database
sudo rkhunter --update

# Update file properties baseline (run after system updates)
sudo rkhunter --propupd

# Check for latest rkhunter version
sudo rkhunter --versioncheck

# List all available tests
rkhunter --list

# Enable only specific tests
sudo rkhunter --check --enable rootkits,trojans --skip-keypress

# Disable specific tests
sudo rkhunter --check --disable apps --skip-keypress

# Cron-friendly check with log output
sudo rkhunter --cronjob --logfile /var/log/rkhunter.log

```

## Notes & Tips

1. Run rkhunter with `sudo` or as root -- most checks require privileged access to examine system binaries and kernel-level indicators.
2. Run `--propupd` after every system update (apt upgrade) to re-baseline file properties; otherwise legitimate changes trigger false positives.
3. Use `--cronjob` for scheduled scans -- it combines quiet mode, warning-only output, and skipped keypresses into a single flag.
4. False positives are expected on heavily customized systems; review the log file at `/var/log/rkhunter.log` for details before concluding compromise.
5. Combine with `chkrootkit` for broader coverage -- each tool uses different detection signatures and heuristics.
6. On a compromised system, run rkhunter from a trusted live environment or use trusted binaries to avoid rootkit interference.
7. The `--list` flag shows all available tests, making it easy to selectively enable or disable checks for targeted scanning.

---

## Official References

- [rkhunter Official Site](https://rkhunter.sourceforge.net/)
- [Kali rkhunter](https://www.kali.org/tools/rkhunter/)
