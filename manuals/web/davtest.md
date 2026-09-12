# davtest

- **Category**: Web / WebDAV Testing
- **Risk Level**: 🟡 Medium

---

## Description

Tests WebDAV servers by uploading test files with various extensions (asp, aspx, php, jsp, cgi, pl, txt, html, etc.) and checking which can be executed. Identifies dangerous file upload and execution capabilities on WebDAV-enabled servers.

WebDAV (Web Distributed Authoring and Versioning) extends HTTP with PUT, DELETE, MKCOL, COPY, and MOVE methods — davtest systematically probes these to map the attack surface. Results show which extensions can be uploaded and which are executed server-side.

## Installation

```bash
sudo apt install davtest
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-url <url>` | Target WebDAV URL |
| `-auth <user:pass>` | Credentials for authentication |
| `-realm <realm>` | Authentication realm |
| `-directory <dir>` | Postfix portion of directory to create |
| `-cleanup` | Delete everything uploaded when done |
| `-rand <name>` | Use this string instead of a random string for filenames |
| `-sendbd <mode>` | Send backdoors: `auto` (for any succeeded test) or `ext` (extension matching) |
| `-uploadfile <file>` | Upload a specific local file (requires -uploadloc) |
| `-uploadloc <path>` | Remote location/name for uploaded file (requires -uploadfile) |
| `-move` | PUT text files then MOVE to executable extension |
| `-copy` | PUT text files then COPY to executable extension |
| `-nocreate` | Do not create a test directory on the server |
| `-debug <1-3>` | DAV debug level (2 & 3 log to /tmp/perldav_debug.txt) |
| `-quiet` | Only print summary results |

## Common Commands

```bash
# Basic WebDAV test — upload test files and check execution
davtest -url http://target.com/webdav/

# Authenticated WebDAV test
davtest -url http://target.com/webdav/ -auth admin:password

# Test with cleanup (remove uploaded files after testing)
davtest -url http://target.com/webdav/ -cleanup

# Send a PHP backdoor after confirming PHP execution
davtest -url http://target.com/webdav/ -sendbd php

# Test MOVE method (bypass extension filters)
davtest -url http://target.com/webdav/ -move

# Upload a specific file to a target location
davtest -url http://target.com/webdav/ -uploadfile /tmp/shell.aspx -uploadloc shell.aspx

# Test in a specific remote directory with custom prefix
davtest -url http://target.com/webdav/ -directory uploads -rand testfile

# Quiet mode — summary output only
davtest -url http://target.com/webdav/ -cleanup -quiet
```

## Notes & Tips

1. Always use `-cleanup` during authorized assessments to remove test artifacts from the target server.
2. The MOVE test (`-move`) is critical — many servers block direct uploads of dangerous extensions but allow renaming via MOVE/COPY.
3. If davtest confirms execution of a file type, follow up with a proper webshell upload for further exploitation.
4. WebDAV misconfigurations are common on IIS servers — test both the root path and virtual directories.
5. Combine with `cadaver` (interactive WebDAV client) for manual file management after confirming access.
6. davtest output shows two columns: "UPLOAD" (whether PUT succeeded) and "EXEC" (whether the file executed server-side). A file that uploads but does not execute is still a finding — it may enable content injection or phishing.
7. Use `-rand` with a unique prefix per engagement to avoid filename collisions with other testers.

---

## Official References

- [davtest GitHub](https://github.com/cldrn/davtest)
- [Kali davtest](https://www.kali.org/tools/davtest/)
