# Recon-ng

- **Category**: Information Gathering / OSINT Framework
- **Risk Level**: 🟡 Medium

---

## Description

Recon-ng is a powerful web reconnaissance framework with a Metasploit-like command-line interface and a modular architecture. It provides a complete environment for automating OSINT reconnaissance tasks and stores data in a database for easy management and analysis.

## Installation

```bash
recon-ng

sudo apt install recon-ng
git clone https://github.com/lanmaster53/recon-ng
cd recon-ng && pip3 install -r REQUIREMENTS

# Install all modules (first-time use)
# ⚠️  Requires internet access; install modules interactively before running batch scripts
# In the recon-ng command line:
marketplace install all
```

## Parameter Reference

### Launch Parameters

| Parameter | Description |
|-----------|-------------|
| `-w <workspace>` | Specify/create workspace |
| `-r <file>` | Load commands from a resource file |
| `--no-version` | Disable version check |
| `--no-analytics` | Disable analytics reporting |
| `--no-marketplace` | Disable remote module management |

### In-Framework Commands

| Command | Description |
|---------|-------------|
| `workspaces create <name>` | Create a workspace |
| `workspaces list` | List workspaces |
| `workspaces load <name>` | Load a workspace |
| `marketplace search [keyword]` | Search for modules |
| `marketplace install <module>` | Install a module |
| `marketplace info <module>` | View module information |
| `modules search [keyword]` | Search installed modules |
| `modules load <module>` | Load a module |
| `info` | View current module information |
| `options set <option> <value>` | Set an option |
| `options list` | List options |
| `run` | Run the current module |
| `back` | Exit the current module |
| `db insert <table> <value>` | Insert a record into the database |
| `db query <SQL>` | Query the database |
| `show <table>` | Display database table contents |
| `keys add <API name> <key>` | Add an API key |
| `keys list` | List configured API keys |
| `dashboard` | View project statistics |
| `pdb` | Python debugger |
| `exit` | Exit the framework |

## Common Commands

### Scenario 1: Initialize Workspace

```bash
# Launch recon-ng
recon-ng

# Create a project workspace
[recon-ng] > workspaces create example_corp

# Install all modules (first-time use)
[recon-ng][example_corp] > marketplace install all

# Install a specific module
[recon-ng][example_corp] > marketplace install recon/domains-hosts/hackertarget
```

### Scenario 2: Configure API Keys

```bash
# View modules that require API keys
[recon-ng] > marketplace search

# Add API keys
[recon-ng] > keys add shodan_api YOUR_SHODAN_API_KEY
[recon-ng] > keys add virustotal_api YOUR_VT_API_KEY
[recon-ng] > keys add github_api YOUR_GITHUB_TOKEN

# View configured keys
[recon-ng] > keys list
```

### Scenario 3: Subdomain Enumeration

```bash
# Add target domain
[recon-ng][example_corp] > db insert domains example.com

# Use multiple modules to enumerate subdomains
[recon-ng][example_corp] > modules load recon/domains-hosts/hackertarget
[recon-ng][example_corp][hackertarget] > run

[recon-ng][example_corp] > modules load recon/domains-hosts/certificate_transparency
[recon-ng][example_corp][certificate_transparency] > run

[recon-ng][example_corp] > modules load recon/domains-hosts/google_site_web
[recon-ng][example_corp][google_site_web] > run

# View discovered hosts
[recon-ng][example_corp] > show hosts
```

### Scenario 4: Contact and Email Collection

```bash
# Search for contact modules
[recon-ng][example_corp] > modules search contacts

# Use the Hunter.io module
[recon-ng][example_corp] > modules load recon/domains-contacts/hunter_io
[recon-ng][example_corp][hunter_io] > options set SOURCE example.com
[recon-ng][example_corp][hunter_io] > run

# View contacts
[recon-ng][example_corp] > show contacts
```

### Scenario 5: IP Address Information

```bash
# Resolve IP addresses for hosts
[recon-ng][example_corp] > modules load recon/hosts-hosts/resolve
[recon-ng][example_corp][resolve] > run

# Shodan lookup
[recon-ng][example_corp] > modules load recon/hosts-ports/shodan_ip
[recon-ng][example_corp][shodan_ip] > run

# View IP information
[recon-ng][example_corp] > show hosts
```

### Scenario 6: Generate Reports

```bash
# HTML report
[recon-ng][example_corp] > modules load reporting/html
[recon-ng][example_corp][html] > options set FILENAME /tmp/report.html
[recon-ng][example_corp][html] > options set CREATOR "Pentester Name"
[recon-ng][example_corp][html] > options set CUSTOMER "Example Corp"
[recon-ng][example_corp][html] > run

# CSV export
[recon-ng][example_corp] > modules load reporting/csv
[recon-ng][example_corp][csv] > options set FILENAME /tmp/hosts.csv
[recon-ng][example_corp][csv] > options set TABLE hosts
[recon-ng][example_corp][csv] > run
```

### Scenario 7: Batch Automation

> **Prerequisite**: Install all required modules interactively (`marketplace install all`) before running a batch script. `marketplace install` in `-r` mode may silently fail if not already installed.

```bash
# Create a commands file
cat > recon_commands.txt << 'EOF'
workspaces create auto_recon
db insert domains example.com
modules load recon/domains-hosts/hackertarget
run
back
modules load recon/hosts-hosts/resolve
run
back
modules load reporting/html
options set FILENAME /tmp/recon_report.html
run
exit
EOF

# Execute automatically
recon-ng -r recon_commands.txt
```

### Database Operations
```bash
# Direct SQL queries
[recon-ng] > db query SELECT * FROM hosts WHERE host LIKE '%.example.com'

# Import known data (interactive; prompts for each field)
[recon-ng] > db insert domains
# (enter values when prompted)

# For domains specifically, direct insert works:
[recon-ng] > db insert domains example.com
```

### Commonly Used Modules

| Module | Function |
|--------|----------|
| `recon/domains-hosts/hackertarget` | Subdomain enumeration |
| `recon/domains-hosts/certificate_transparency` | Certificate transparency |
| `recon/domains-contacts/hunter_io` | Email collection |
| `recon/hosts-hosts/resolve` | DNS resolution |
| `recon/hosts-ports/shodan_ip` | Shodan lookup |
| `recon/hosts-hosts/bing_ip` | Bing IP lookup |
| `recon/domains-vulnerabilities/xssed` | XSS vulnerabilities |
| `reporting/html` | HTML report |
| `reporting/csv` | CSV export |

## Notes & Tips

1. Install marketplace modules interactively before relying on `-r` batch execution.
2. Use separate workspaces for separate clients or assessment scopes to avoid mixing evidence.
3. Many modules require API keys; configure keys before concluding a data source has no results.
4. Use `reporting/html` or `reporting/csv` to export database contents for reports.
5. For focused subdomain enumeration, cross-check recon-ng results with `theHarvester`, `amass`, `subfinder`, and `spiderfoot`.

---

## Official References

- [recon-ng GitHub](https://github.com/lanmaster53/recon-ng)
- [recon-ng Wiki](https://github.com/lanmaster53/recon-ng/wiki)
