# ldeep

- **Category**: Information Gathering / LDAP Enumeration
- **Risk Level**: 🟡 Medium

---

## Description

ldeep is an LDAP enumeration tool for Active Directory environments. It extracts users, groups, computers, GPOs, trusts, delegations, and other AD objects via LDAP queries. Supports both password-based and NTLM hash-based authentication, as well as certificate-based (PFX) connections. Serves as an AD-focused alternative to ldapsearch with purpose-built enumeration modules. Written in Python.

## Installation

```bash
sudo apt install ldeep

ldeep --help

# Or install via pip
pip3 install ldeep
```

## Parameter Reference

### Connection Parameters (ldap subcommand)

| Parameter | Description |
|-----------|-------------|
| `ldap` | Use LDAP connection mode (subcommand) |
| `-d <domain>` | Target AD domain (e.g., `corp.local`) |
| `-s <server>` | LDAP server URL (e.g., `ldap://10.0.0.1` or `ldaps://10.0.0.1:636`) |
| `-u <user>` | Username for authentication |
| `-p <password>` | Password for authentication |
| `-H <hash>` | NTLM hash for pass-the-hash authentication (format: `LMHASH:NTHASH`) |
| `--pfx-file <cert>` | PFX certificate file for certificate-based authentication |
| `-o <file>` | Store results in output file |
| `--security_desc` | Retrieve security descriptors |

### Enumeration Modules

| Parameter | Description |
|-----------|-------------|
| `users` | Enumerate all domain users |
| `groups` | Enumerate all domain groups |
| `machines` | Enumerate all domain computers |
| `trusts` | Enumerate domain trusts |
| `zones` | Enumerate DNS zones |
| `pso` | Enumerate Password Settings Objects (fine-grained password policies) |
| `gpo` | Enumerate Group Policy Objects |
| `ou` | Enumerate Organizational Units |
| `delegations` | Enumerate Kerberos delegations |
| `membersof <group>` | List members of a specific group |
| `memberships <user>` | List group memberships for a user |
| `from_sid <SID>` | Resolve a SID to its AD object |
| `sddl <object>` | Display SDDL security descriptor for an object |
| `object <identity>` | Query a specific AD object by distinguished name or sAMAccountName |

## Common Commands

### Scenario 1: Basic Domain Enumeration

```bash
# Enumerate all domain users
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -p 'P@ssw0rd' users

# Enumerate all domain groups
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -p 'P@ssw0rd' groups

# Enumerate all domain computers
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -p 'P@ssw0rd' machines
```

### Scenario 2: Pass-the-Hash Authentication

```bash
# Authenticate with NTLM hash
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c users

# Enumerate trusts with hash authentication
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c trusts
```

### Scenario 3: Group and Membership Analysis

```bash
# List members of Domain Admins
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -p 'P@ssw0rd' membersof "Domain Admins"

# List all group memberships for a user
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -p 'P@ssw0rd' memberships jdoe

# Enumerate Organizational Units
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -p 'P@ssw0rd' ou
```

### Scenario 4: Security-Focused Enumeration

```bash
# Enumerate Kerberos delegations (unconstrained, constrained, RBCD)
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -p 'P@ssw0rd' delegations

# Enumerate GPOs
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -p 'P@ssw0rd' gpo

# Enumerate fine-grained password policies
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -p 'P@ssw0rd' pso

# Resolve a SID
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -p 'P@ssw0rd' from_sid S-1-5-21-123456789-123456789-123456789-1001
```

### Scenario 5: Certificate-Based Authentication

```bash
# Authenticate using a PFX certificate
ldeep ldap -d corp.local -s ldap://10.0.0.1 --pfx-file user_cert.pfx users
```

### Scenario 6: DNS and Object Queries

```bash
# Enumerate DNS zones
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -p 'P@ssw0rd' zones

# Query SDDL security descriptor for an object
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -p 'P@ssw0rd' sddl "CN=Domain Admins,CN=Users,DC=corp,DC=local"

# Query a specific AD object
ldeep ldap -d corp.local -s ldap://10.0.0.1 -u jdoe -p 'P@ssw0rd' object jdoe
```

## Notes & Tips

1. ldeep requires valid domain credentials (password, NTLM hash, or PFX certificate). It does not support anonymous LDAP binds.
2. Use pass-the-hash (`-H`) when you have extracted NTLM hashes but not plaintext passwords — avoids the need for password cracking.
3. The `delegations` module is critical for identifying Kerberos delegation misconfigurations (unconstrained delegation, constrained delegation, resource-based constrained delegation) that are common AD attack paths.
4. Output is plain text to stdout. Redirect to files or pipe through `jq` / `grep` for filtering large result sets.
5. Combine with BloodHound for graphical AD attack path analysis: use ldeep for quick targeted queries and BloodHound for comprehensive relationship mapping.

---

## Official References

- [ldeep (GitHub)](https://github.com/franc-pentest/ldeep)
- [Kali ldeep](https://www.kali.org/tools/ldeep/)
