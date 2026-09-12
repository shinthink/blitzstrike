# kiterunner

- **Category**: Web / API Endpoint Discovery
- **Risk Level**: 🟡 Medium

---

## Description

API endpoint discovery tool that understands structured routes and API wordlists. It is useful for REST API path discovery where conventional directory brute-forcing misses parameterized routes.

## Installation

```bash
# Download the latest release binary for your architecture from the official repository
# (releases are published as kr-linux-amd64 / kr-linux-arm64 etc. — match your platform)
curl -L https://github.com/assetnote/kiterunner/releases/latest/download/kr-linux-amd64 -o kr
chmod +x kr
sudo mv kr /usr/local/bin/
kr -h
```

> Note: the executable name depends on how it was installed. On this Kali host the binary is installed as `kiterunner` (the official release ships as `kr`). Use whichever name resolves on your `$PATH` — the subcommands and flags are identical.

## Parameter Reference

| Parameter | Description |
|------|------|
| `scan` | Scan targets using kite wordlists |
| `brute` | Brute-force targets using plain-text wordlists |
| `-w <wordlist>` | Kite or plain-text wordlist |
| `-A <type/name>` / `--assetnote-wordlist` | Use Assetnote wordlists (e.g. `apiroutes-210228`) |
| `-x <n>` / `--max-connection-per-host` | Max connections per host (default `3`) |
| `-j <n>` / `--max-parallel-hosts` | Max parallel hosts (default `50`) |
| `-d <n>` / `--preflight-depth` | Preflight wildcard check directory depth; `0` checks only the docroot (scan default: `1`) |
| `-H <header>` | Custom header |
| `-o <format>` | Output format: `json`, `text`, `pretty` (default: `pretty`) |
| `--success-status-codes <codes>` | Whitelist status codes as successful |
| `--fail-status-codes <codes>` | Blacklist status codes as failures |
| `--force-method <method>` | Override HTTP method for all requests |
| `-t <duration>` / `--timeout` | Request timeout (default `3s`) |
| `--max-redirects <n>` | Max redirects to follow (default `3`) |
| `--ignore-length <range>` | Content-length byte ranges to ignore (e.g. `100-105` or `1234,34-53`) |
| `--disable-precheck` | Skip host discovery / preflight |
| `--kitebuilder-full-scan` | Full scan without first doing a phase scan |
| `--delay <duration>` | Delay inserted between requests to a single host |
| `--quarantine-threshold <n>` | Quarantine a host as wildcard after N consecutive hits (0 disables; default 10) |
| `-q` / `--quiet` | Quiet mode (mute pretty text) |
| `-v <level>` / `--verbose` | Logging verbosity: `error,info,debug,trace` (default `info`) |
| `--config <file>` | Config file (default `$HOME/.kiterunner.yaml`) |

## Common Commands

```bash
# Scan API targets with kite wordlist (output to file via redirect)
kr scan targets.txt -w <api_wordlist.kite> | tee /tmp/kiterunner.txt

# Scan one API base URL
echo https://target/api | kr scan - -w <api_wordlist.kite>

# Brute-force with a plain-text wordlist
kr brute https://target/api -w /usr/share/wordlists/dirb/common.txt

# Use Assetnote wordlists
kr scan targets.txt -A apiroutes-210228

# Limit connections and force GET method
kr scan targets.txt -w <api_wordlist.kite> -x 3 --force-method GET
```

## Notes & Tips

1. Use after identifying API base paths with `katana`, ZAP, or traffic captures.
2. Calibrate negative status codes and response lengths to reduce false positives.
3. Kiterunner is active enumeration; respect rate limits.

---

## Official References

- [Kiterunner GitHub](https://github.com/assetnote/kiterunner)

