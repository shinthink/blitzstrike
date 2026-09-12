# Penetration Test Report Template

- **Category**: Reporting / Template
- **Risk Level**: 🟢 Low

---

## Description

Reusable penetration test report template for final deliverables. Use this file to structure executive summaries, scope, findings, evidence, remediation guidance, and appendices.

## Installation

Not applicable. This is a reusable documentation template, not an installable command-line tool.

## Parameter Reference

| Parameter | Description |
|-----------------------|-------------|
| `{Client Name}` | Client or engagement name |
| `{IP/Domain}` | Authorized test scope |
| `{Start Date} ~ {End Date}` | Testing period |
| `{Vulnerability Name}` | Finding title |
| `{System/Location}` | Affected system, endpoint, or asset |
| `{impact description}` | Business or technical impact summary |
| `F-###` | Finding identifier format |
| CVSS fields | Standard CVSS vector values for severity scoring |

## Common Commands

### Complete Report Structure

````markdown
# Penetration Test Report
**Client**: {Client Name}  
**Scope**: {IP/Domain}  
**Test Period**: {Start Date} ~ {End Date}  
**Test Type**: Black-box / Grey-box / White-box  
**Report Date**: {Date}  
**Report Version**: v1.0  
**Confidentiality**: Confidential

---

## Executive Summary (For Management)

(Non-technical language, within 500 words)

This penetration test identified **X security vulnerabilities**, including:
- 🔴 Critical: X (requires immediate remediation)
- 🟠 High: X (remediate within 1 week)
- 🟡 Medium: X (remediate within 1 month)
- 🟢 Low: X (remediate within a reasonable timeframe)

The most severe finding is **{Vulnerability Name}**, located at **{System/Location}**,
which could allow an attacker to **{impact description}**.

**Key Recommendations**:
1. Immediately remediate the SQL injection vulnerability (F-001)
2. Update Apache to the latest version (F-003)
3. Enable a Web Application Firewall (WAF)

---

## Scope

### In-Scope
- IP/Domain 1
- IP/Domain 2

### Out-of-Scope
- IP/Domain X (critical production system, passive testing only)

### Testing Constraints
- Testing hours: Weekdays 09:00–18:00
- No DoS attacks permitted
- No data modification permitted

---

## Vulnerability Summary

| ID | Vulnerability | Risk | Affected Asset | CVSS | Status |
|----|---------|------|-----------|------|------|
| F-001 | SQL Injection | 🔴 Critical | /api/login | 10.0 | Open |
| F-002 | Directory Traversal | 🟠 High | /files/ | 7.5 | Open |
| F-003 | Outdated Apache | 🟡 Medium | 192.168.1.100 | 5.3 | Open |
| F-004 | Weak Password Policy | 🟡 Medium | SSH service | 4.9 | Open |
| F-005 | Sensitive Information Disclosure | 🟢 Low | robots.txt | 2.7 | Open |

---

## Attack Chain

(Document how individual findings chain together to achieve the final compromise. Show the step-by-step progression from initial access to maximum impact. Include each finding ID used in the chain and the causal link between steps.)

**Chain 1: {Chain Title}**
1. {F-XXX} — {initial access step}
2. {F-XXX} — {escalation step}
3. {F-XXX} — {final impact}

**Overall Impact**: {combined impact that exceeds individual finding severities}

---

## Vulnerability Details

### F-001: SQL Injection (Critical)

**Affected Location**: `POST http://target.com/api/login`  
**Affected Parameter**: `username`  
**Vulnerability Type**: SQL Injection (error-based)  
**CVSS Score**: 10.0 (AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)  
**CWE**: CWE-89

**Description**:
The `username` parameter on the login endpoint does not use parameterized queries.
An attacker can inject malicious SQL to bypass authentication entirely
and read, modify, or delete all data in the database.

**Reproduction Steps**:
1. Navigate to `http://target.com/login`
2. Enter in the username field: `admin' OR '1'='1`
3. Enter any value in the password field and click Login
4. Successfully log in as an administrator

**Evidence (Screenshot/Output)**:
```
$ sqlmap -u "http://target.com/api/login" --data="username=test&password=test" --batch
[INFO] Parameter 'username' is vulnerable
[INFO] the back-end DBMS is MySQL
[INFO] retrieved: admin, password_hash, email from users table
```

**Impact**:
- Attacker can log in as any administrator account
- Can read all user data (including password hashes, emails, personal information)
- May result in complete database exfiltration

**Remediation**:
1. **Immediately**: Replace string concatenation with parameterized queries (Prepared Statements)
   ```python
   # Vulnerable code
   query = "SELECT * FROM users WHERE username='" + username + "'"
   # Fixed code
   query = "SELECT * FROM users WHERE username = %s"
   cursor.execute(query, (username,))
   ```
2. Apply strict validation and filtering to all user input
3. Configure WAF rules to detect SQL injection patterns
4. Minimize database account privileges (do not use root)
5. Do not return error messages to the client

**References**:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html

---

(Fill in remaining findings using the same format)

---

## Testing Activity Log

| Time | Phase | Action | Tool | Finding |
|------|------|------|------|------|
| 09:00 | Reconnaissance | Port scan | nmap | Open ports: 22/80/443/8080 |
| 09:30 | Reconnaissance | Web fingerprinting | whatweb | Apache 2.4.49, PHP 7.4 |
| 10:00 | Scanning | WAF detection | wafw00f | No WAF detected |
| 10:15 | Scanning | Directory enumeration | gobuster | Found /admin /backup |
| 10:45 | Web | SQL injection testing | sqlmap | **F-001 SQL Injection (Critical)** |
| 11:30 | Web | XSS testing | dalfox | No XSS found |

---

## Appendices

### A. Tools Used
| Tool | Version | Purpose |
|------|------|------|
| nmap | 7.94 | Port scanning |
| nikto | 2.1.6 | Web vulnerability scanning |
| sqlmap | 1.7.12 | SQL injection detection |

### B. References
- OWASP Top 10: https://owasp.org/Top10/
- NIST NVD: https://nvd.nist.gov/
- CVE Details: https://www.cvedetails.com/

### C. Disclaimer
This penetration test was conducted under an authorization agreement signed by both parties.
All testing activities were performed within the agreed scope.
The testers bear no responsibility for system anomalies resulting from testing activities.
````

### Risk Level Definitions

| Level | CVSS | Remediation Timeline | Description |
|------|------|---------|------|
| 🔴 Critical | 9.0–10.0 | Immediately (within 24h) | Remotely exploitable without authentication, leads directly to system compromise |
| 🟠 High | 7.0–8.9 | Within 1 week | Exploitable, severely impacts confidentiality/integrity/availability |
| 🟡 Medium | 4.0–6.9 | Within 1 month | Requires specific conditions, limited impact |
| 🟢 Low | 0.1–3.9 | Reasonable timeframe | Difficult to exploit directly, minor impact |
| ⚪ Informational | 0.0 | As needed | Configuration improvement suggestions, no direct threat |

### CVSS Quick Reference

```text
CVSS v4.0 Base Metrics:
AV: Network(N) / Adjacent(A) / Local(L) / Physical(P)
AC: Low(L) / High(H)
AT: None(N) / Present(P)
PR: None(N) / Low(L) / High(H)
UI: None(N) / Passive(P) / Active(A)
VC/VI/VA: High(H) / Low(L) / None(N)    (Vulnerable system)
SC/SI/SA: High(H) / Low(L) / None(N)    (Subsequent system)

Online Calculator: https://www.first.org/cvss/calculator/4.0
```

### Placeholder Rules

Use these rules to populate placeholders automatically:

| Placeholder | Source |
|-------------|--------|
| `{Client Name}` | Extract from user message — look after "client:", "target:", "assessment:", "company:" |
| `{IP/Domain}` | Collect from authorized scope confirmation at the start of the engagement |
| `{Start Date} ~ {End Date}` | Timestamp of the first command run and the last command run; use `date -I` format |
| `{Vulnerability Name}` | From nuclei `info.name`, sqlmap result, or manual finding title |
| `{System/Location}` | From nuclei `host` field, `matched-at` URL, or nmap target |
| `{impact description}` | Infer from vulnerability type: SQLi → "unauthorized database access", RCE → "full system compromise" |
| `F-###` | Auto-number: sort findings by severity (Critical→High→Medium→Low), assign F-001, F-002, ... |
| CVSS fields | If tool output includes CVE number, look up CVSS at NVD; otherwise estimate from the CVSS Quick Reference table below |
| Tools Used table | Extract tool names and versions from `{tool} --version 2>&1` or `{tool} -h` output during testing |

### Data Extraction Commands

```bash
# 1. Extract severity, name, and host from nuclei JSONL
cat nuclei_findings.jsonl | jq -r '[.info.severity, .info.name, .host] | @tsv' | sort -k1,1 | nl -ba -nrz -w3 | awk -F'\t' '{printf "F-%s\t%s\t%s\t%s\n", $1, $2, $3, $4}' > findings.tsv

# 2. Extract SQL injection results
grep -E "Parameter|vulnerable|back-end" /tmp/sqlmap/*/log | sed 's/^/F-SQL-/'

# 3. Extract open ports from nmap XML
grep '<port protocol="tcp".*state="open"' scan.xml | grep -oP 'portid="\K[^"]+' | sort -n | paste -sd ','
```

## Notes & Tips

1. Keep the executive summary non-technical and focused on business impact.
2. Every finding should include affected assets, reproducible evidence, impact, and remediation guidance.
3. Preserve authorization scope and testing constraints in the final report.

---

## Official References

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10](https://owasp.org/Top10/)
- [FIRST CVSS](https://www.first.org/cvss/)
