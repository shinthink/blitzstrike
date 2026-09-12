---
name: ad-ntds-escalation
description: Use when attacking AD with any foothold. PTH to NTDS ladder.
---

# AD Escalation Ladder — foothold to NTDS (reusable)

Generic escalation ladder for authorized AD engagements (CTF labs, owned
ranges). Ordered cheapest-first; stop at the first rung that lands.

## Rung 0 — Triage (do first, always)
1. **Clock sync**: DC time via `nmap -Pn -p445 --script smb2-time <dc>` then
   `sudo date -s '<dc-time> UTC'`. Kerberos dies on skew; this is the #1
   false-blocker. Never debug auth before syncing.
2. Hosts entry for FQDN of DC (Kerberos needs hostname, not IP).
3. Try EVERY credential recovered from ANY previous session/machine before
   inventing new attacks — **NT hashes frequently outlive respawns/restarts**.
   Test: `nxc smb <dc> -u <user> -H <hash> -d <domain>`.

## Rung 1 — With a user account (any)
- LDAP anonymous: domain, hostname, users (ldap3 ANONYMOUS bind).
- bloodyAD: `set restore <user>` for tombstones if Reanimate rights.
- Enumerate groups of owned users: BackupAccess/Remote Management Users/
  Account Operators = direct paths.

## Rung 2 — WinRM as non-admin service account
- `nxc winrm <dc> -u <user> -H <hash> -d <dom>` — `Pwn3d!` = shell.
- TOOL GOTCHAS (verified):
  - `nxc` is the ONLY reliable hash-auth WinRM path. pywinrm rejects hashes.
  - `getTGT.py` fails with KDC_ERR_ETYPE_NOSUPP on AES-only KDCs (RC4
    disabled) — don't burn time; NTLM-over-SMB/WinRM still works.
  - `wmiexec`/`smbexec` may give rpc_s_access_denied even when WinRM works —
    they need service/WMI rights the account may lack. nxc uses WinRM only.

## Rung 3 — Admin on a DC
- `secretsdump.py '<DOM>/Administrator@<dc>' -hashes :<nthash>` → SAM, LSA,
  NTDS (all users + krbtgt + DA). Run BACKGROUNDED: NTDS takes 5–10 min;
  foreground timeouts kill the run mid-dump.
- LSA DefaultPassword often holds a plaintext service-account password.

## Rung 4 — DA
- PTH as DA → read flags/data, dump anything. Verify with
  `nxc smb <dc> -u <da> -H <hash>` → Pwn3d!

## Memory-efficiency rules
- Save all hashes to the box workdir SOLVED.md immediately (verified only).
- Hashes beat passwords: prefer PTH (no cleartext needed anywhere).
- One username+hash pair that worked = test it on EVERY service before
  escalating further (SMB/WinRM/MSSQL/LDAP).
