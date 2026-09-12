# Amass

- **Category**: Information Gathering / Subdomain Enumeration / Attack Surface Discovery
- **Risk Level**: 🟡 Medium

---

## Description

Amass is an OWASP project for subdomain enumeration and network attack surface discovery, and is one of the most powerful subdomain enumeration tools available. It integrates over 50 data sources, supports both active and passive enumeration modes, and provides visual network topology maps.

## Installation

```bash

amass -version     # v3 style; v4/v5 uses: amass version

# Also works
amass -h

sudo apt install amass

# Install latest version using Go (v4/v5)
go install -v github.com/owasp-amass/amass/v4/...@master
# ⚠️  amass v5 (current Kali default) significantly restructured config format and subcommands vs v3
#    v5 adds: engine, subs, assoc subcommands; removes intel, db
#    The examples below apply primarily to v3/v4 style. v5 behavior may differ — check `amass -h`.

# Configure API keys (strongly recommended)
mkdir -p ~/.config/amass
# Copy example config:
# v3 (Kali default) uses INI format:
# The example path varies by Kali/distro version; common locations:
#   /usr/share/amass/examples/config.ini
#   /usr/share/doc/amass/examples/config.ini
# Try both; if neither exists, copy from the GitHub repo or create from scratch.
cp /usr/share/amass/examples/config.ini ~/.config/amass/config.ini 2>/dev/null || \
  cp /usr/share/doc/amass/examples/config.ini ~/.config/amass/config.ini
# v4/v5 (Go install) uses YAML format:
# cp /usr/share/amass/examples/config.yaml ~/.config/amass/config.yaml
# Edit the config file to fill in API Keys for each data source
```

## Parameter Reference

### Subcommands

> ⚠️  **v5 (current Kali default) has significantly restructured subcommands vs v3/v4. See the version notes below.**

**v5 subcommands (current Kali default — v5.x):**

| Parameter | Description |
|-----------|-------------|
| `enum` | Interface with the enumeration engine |
| `engine` | Run the collection engine to populate the OAM database |
| `subs` | Analyze and present discovered subdomains |
| `track` | Identify newly discovered assets |
| `viz` | Generate graph visualizations |
| `assoc` | Query the OAM along walk-defined triples |

**v3/v4 subcommands (legacy; shown for reference):**

| Parameter | Description |
|-----------|-------------|
| `enum` | Subdomain enumeration (core feature) |
| `intel` | Target organization information gathering |
| `viz` | Visualize results as charts |
| `track` | Track changes in assets |
| `db` | Manage the database |

### enum Subcommand Parameters

> Verified against **amass v5.1.1** (current Kali default) via `amass enum -h`. The flag set below is what v5 actually accepts. **v5 removed** several v3/v4 flags that older guides still show: `-o`, `-json`, `-src`, `-ip`, `-ipv4`, `-ipv6`, `-nolocaldb`, `-max-dns-queries`, `-dns-qps`, `-share`, `-include-unresolvable`, `-ef`, `-if`. Use `-oA <prefix>` for output (a path prefix for naming output files; a trailing slash like `out/` writes them under that directory) and the YAML config / engine database for the rest.

| Parameter | Description |
|-----------|-------------|
| `-d <domain>` | Target domain(s), comma-separated or repeatable (e.g. `-d example.com`) |
| `-df <file>` | Read root domain names from a file |
| `-oA <prefix>` | Path prefix used for naming all output files (v5 output flag) |
| `-passive` | Passive mode — no active queries (deprecated: passive is now the default) |
| `-active` | Active mode (zone transfers and certificate name grabs) |
| `-brute` | Execute brute forcing after searches |
| `-w <file>` | Wordlist file for brute forcing |
| `-alts` | Enable generation of altered names |
| `-aw <file>` | Wordlist file for name alterations |
| `-awm <mask>` | hashcat-style wordlist masks for alterations |
| `-min-for-recursive <n>` | Minimum subdomain count to trigger recursive brute forcing |
| `-norecursive` | Turn off recursive brute forcing |
| `-max-depth <n>` | Maximum number of subdomain labels for brute forcing |
| `-r <resolver>` | Custom DNS resolver(s), comma-separated |
| `-rf <file>` | Read DNS resolvers from a file |
| `-bl <domain>` | Blacklist a subdomain name from investigation |
| `-blf <file>` | Read blacklisted subdomains from a file |
| `-addr <ip/range>` | IPs and ranges (e.g. `192.168.1.1-254`), comma-separated |
| `-asn <asn>` | ASNs, comma-separated (repeatable) |
| `-cidr <cidr>` | CIDRs, comma-separated (repeatable) |
| `-p <port>` | Ports separated by commas (default: 80, 443) |
| `-exclude <source>` | Exclude specific data source(s) by name |
| `-include <source>` | Use only the specified data source(s) |
| `-nf <file>` | Path to a file providing already-known subdomain names |
| `-config <file>` | Path to the YAML configuration file |
| `-dir <dir>` | Path to the output / OAM database directory |
| `-engine <addr>` | Address of an external Amass engine to use |
| `-iface <iface>` | Provide the network interface to send traffic on |
| `-timeout <minutes>` | Minutes to run without progress before terminating (default: 30) |
| `-tr <ip>` | IP addresses of trusted DNS resolvers (repeatable) |
| `-rigid` | Disable scope expansion |
| `-list` | List available data sources and exit |
| `-silent` | Disable all output during execution |
| `-nocolor` | Disable colorized output |
| `-demo` | Censor output to make it suitable for demonstrations |
| `-v` | Verbose output |
| `-log <file>` | Path to a log file |

## Common Commands

### Scenario 1: Quick Passive Enumeration (v5)

```bash
# Passive mode enumeration (fastest, no active queries)
amass enum -passive -d example.com

# Passive enumeration of multiple domains, write all output formats to a directory
amass enum -passive -df domains.txt -oA results/
```

> v5 note: `-ip`/`-src`/`-o`/`-json` were removed. Output goes to the `-oA <prefix>` set (and the OAM database); query/format it afterward with `amass subs` / `amass viz`.

### Scenario 2: Active Enumeration (More Comprehensive) (v5)

```bash
# Default enumeration (passive is the default in v5; this does NOT do active queries)
amass enum -d example.com

# Enable DNS brute-forcing
amass enum -brute -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Active mode — add -active to attempt zone transfers and certificate name grabs
amass enum -active -d example.com

# Full enumeration (active + brute-force) writing all formats with output prefix
amass enum -active -brute -d example.com -oA full_enum/
```

### Scenario 3: Subdomain analysis & asset discovery by IP/ASN/CIDR (v5)

```bash
# Enumerate by IP ranges / ASN / CIDR (v5 folds the old `intel` features into enum)
amass enum -addr 203.0.113.1-254 -d example.com
amass enum -asn 12345
amass enum -cidr 203.0.113.0/24

# Analyze and present discovered subdomains from the OAM database
amass subs -d example.com -dir ./amass_output
```

> v5 note: the standalone `amass intel` and `amass db` subcommands were **removed**. Organization/ASN/CIDR discovery now runs through `amass enum` (with `-addr`/`-asn`/`-cidr`), and database queries through `amass subs` / `amass assoc` against the `-dir` OAM database. The `intel`/`db` examples only apply to legacy v3/v4.

### Scenario 4: Persistence and Tracking (v5)

```bash
# Save results / OAM database to a specified directory
amass enum -d example.com -dir ./amass_output

# Track newly discovered assets against the existing database
amass track -d example.com -dir ./amass_output

# Analyze and present discovered subdomains from the database
amass subs -d example.com -dir ./amass_output
```

> v5 note: `amass db` was removed; use `amass subs` / `amass assoc` to query the OAM database under `-dir`.

### Scenario 5: Visualization (v5)

```bash
# Generate D3.js / HTML visualization from the OAM database
amass viz -d3 -dir ./amass_output

# Generate Gephi GEXF format (for advanced graph analysis)
amass viz -gexf -dir ./amass_output

# Generate Graphviz DOT format
amass viz -dot -dir ./amass_output
```

> v5 note: the Gephi output flag is `-gexf` (v3/v4 called it `-gephi`). `amass viz` also supports `-o <file>`/`-oA <prefix>` and `-since <date>`.

### Scenario 6: Using API Keys (Recommended)

```ini
# ~/.config/amass/config.ini example configuration (v3/v4 — INI format)
# Note: amass v5 (current Kali default, Go install) uses YAML format instead; see installation notes above.

[data_sources.SecurityTrails]
[data_sources.SecurityTrails.Credentials]
apikey = YOUR_API_KEY

[data_sources.Shodan]
[data_sources.Shodan.Credentials]
apikey = YOUR_API_KEY

[data_sources.VirusTotal]
[data_sources.VirusTotal.Credentials]
apikey = YOUR_API_KEY

[data_sources.Censys]
[data_sources.Censys.Credentials]
apikey = YOUR_API_ID
secret = YOUR_SECRET
```

```bash
# Use configuration file (automatically loads API keys; v3/v4 style)
amass enum -d example.com -config ~/.config/amass/config.ini
```

## Notes & Tips

1. Configuring API keys significantly increases discovered subdomains — at minimum, configure VirusTotal and Shodan. View supported data sources with `amass enum -list`.
2. **v5 moved IP display out of `enum`**: to show resolved IPs, query the OAM database afterward with `amass subs -d example.com -dir <dir> -ip` (also supports `-ipv4`/`-ipv6`/`-names`/`-summary`/`-o`).
3. Custom DNS resolvers (`-r 8.8.8.8,1.1.1.1`) improve speed and stability over system defaults; `-rf <file>` loads a resolver list.
4. `-timeout 30` terminates enumeration after 30 minutes **without progress** (not a hard total-runtime cap).
5. v5 dropped the `-dns-qps` / `-max-dns-queries` flags — DNS rate tuning now lives in the YAML config file and the engine. Older guides showing `-dns-qps` apply to v3/v4 only.

---

## Official References

- [OWASP Amass GitHub](https://github.com/owasp-amass/amass)
- [Amass Documentation](https://owasp-amass.github.io/docs)
