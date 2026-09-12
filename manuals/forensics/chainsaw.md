# Chainsaw

- **Category**: Forensics / Windows Event Log Analysis
- **Risk Level**: 🟢 Low

---

## Description

A high-speed forensic tool for hunting threats in Windows Event Logs (EVTX), MFT files, and other Windows artifacts. Uses Sigma rules and custom Chainsaw detection rules to identify attacker techniques, suspicious commands, and IoCs across large collections of logs. Essential for both red team operators checking if their actions were logged, and incident responders performing threat hunting.

## Installation

```bash
sudo apt install chainsaw
```

## Parameter Reference

### `chainsaw hunt <dir>` — Hunt using detection rules

| Parameter | Description |
|-----------|-------------|
| `-s <dir>` | Path containing Sigma rules to hunt with |
| `-r <dir>` | Path containing additional rules to hunt with |
| `--mapping <file>` | Mapping file to tell Chainsaw how to use third-party rules |
| `--json` | Print output in JSON format |
| `--csv` | Print output in CSV format |
| `-o <file>` | Path to output results to |

### `chainsaw search <keyword> <dir>` — Search for keywords

| Parameter | Description |
|-----------|-------------|
| `-e <regex>` | String or regular expression pattern to search for |
| `-t <filter>` | Tau expression to search with (e.g., `Event.System.EventID: =4104`) |
| `--json` | Print output in JSON format |
| `-i` | Ignore case when matching patterns (`--ignore-case`) |

## Common Commands

```bash
# Hunt for threats using Sigma rules
chainsaw hunt /mnt/evidence/evtx/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/

# Hunt and output JSON
chainsaw hunt /mnt/evidence/evtx/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml --json -o results.json

# Search for mimikatz indicators
chainsaw search mimikatz /mnt/evidence/evtx/

# Search for PowerShell events (Event ID 4104)
chainsaw search -t 'Event.System.EventID: =4104' /mnt/evidence/evtx/

# Search for specific regex pattern
chainsaw search -e "powershell.*-enc" /mnt/evidence/evtx/

# Dump events to JSON for manual review
chainsaw dump /mnt/evidence/evtx/ --json -o events.json
```

## Notes & Tips

1. Download Sigma rules and mappings separately: `git clone https://github.com/SigmaHQ/sigma.git`
2. Chainsaw is extremely fast — processes thousands of EVTX files in seconds using parallel threads.
3. Use `hunt` for automated threat detection; use `search` for targeted keyword or regex hunting.
4. As a red teamer, use Chainsaw against your own attack logs to verify what evidence you left behind.
5. Pair with Volatility3 for memory forensics and Chainsaw for event log analysis in incident response workflows.

---

## Official References

- [Chainsaw (GitHub)](https://github.com/WithSecureLabs/chainsaw)
- [Kali chainsaw](https://www.kali.org/tools/chainsaw/)
