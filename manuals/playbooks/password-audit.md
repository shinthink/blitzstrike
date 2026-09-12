# Password Audit Playbook

Use for authorized password cracking, hash analysis, default credential checks, password spraying, or credential reuse testing.

## Inputs

- Hash files, credential lists, usernames, target services, and scope.
- Lockout policy, allowed rate, allowed time window, and account exclusions.
- Whether GPU cracking is available and authorized.

## Workflow

1. **Password policy analysis**
   - Before testing, analyze the target's password policy: minimum length, complexity requirements (uppercase, lowercase, digits, special characters), maximum length, and character restrictions.
   - Determine lockout thresholds: number of failed attempts before lockout, lockout duration, and reset behavior.
   - Identify rotation requirements and password history depth.
   - Use this information to focus wordlist selection, rule generation, and mask design — skip candidates that violate the known policy.

2. **Classify material**
   - Identify hash types with `hashid`, tool context, or source system.
   - Separate hashes, plaintext credentials, usernames, and service targets.

   (See `../password/README.md` for hash identification tool selection.)
   - **Hash extraction sources**: SAM database (local Windows accounts), NTDS.dit (Active Directory domain hashes via `impacket-secretsdump`), `/etc/shadow` (Linux/Unix), database credential tables, application configuration files, and memory dumps. Cross-reference `post-exploitation.md` for extraction methods and access prerequisites.

   Use `hashid -m` to identify hash types and get hashcat mode numbers (see `../password/tools/hashid.md`).

   **Ambiguous hash identification:** When hashid returns multiple candidates, narrow by: (1) source context (shadow → sha512crypt/md5crypt; NTDS.dit → NT; Responder → NetNTLMv2), (2) hash length and character set, (3) test top candidates with a small wordlist before running the full escalation ladder.

3. **Prepare wordlists and rules**
   - Use `rockyou.txt`, SecLists, `cewl`, `crunch`, and target-specific terms.
   - Avoid generating huge wordlists unless Deep depth is authorized.

   (See `../password/README.md` for wordlist generation tool selection.)

   Generate custom wordlists with `cewl` and `crunch` (see `../password/tools/cewl.md` and `../password/tools/crunch.md`).

4. **Offline cracking**
   - Use `john` or `hashcat` based on hash type and hardware.
   - Check `hashcat -I` before GPU assumptions.
   - Save cracked results and potfile context.

   (See `../password/README.md` for cracking tool selection.)
   - Select attack mode based on hash type and known password policy:
     - `-a 0` dictionary attack: use with rules for most scenarios. Apply `-r /usr/share/hashcat/rules/best64.rule` for common mutations; chain multiple rule files for deeper coverage.
     - `-a 3` mask/brute-force: use for short passwords or when policy allows short lengths. Define masks matching known policy (e.g., `?u?l?l?l?d?d` for 6-char passwords starting uppercase).
     - `-a 6` hybrid (wordlist + mask append): use when passwords likely follow a base-word-plus-suffix pattern (e.g., `Password1!`). Append digits/symbols to dictionary words.
   - When hash type is slow (bcrypt, scrypt, Argon2, phpass, sha512crypt), prioritize targeted wordlists and smart rules over exhaustive brute force.

   Run offline cracking:
   - GPU preferred: `hashcat -m <mode> -a 0 hashes.txt <wordlist>` (see `../password/tools/hashcat.md` for attack modes and rule files)
   - CPU fallback: `john --wordlist=<wordlist> --format=<format> hashes.txt` (see `../password/tools/john.md`)

   ```bash
   # Dictionary with rules
   hashcat -m <mode> -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
   # Mask attack for 8-char passwords (upper + lower + digits)
   hashcat -m <mode> -a 3 hashes.txt ?u?l?l?l?l?l?d?d
   # Hybrid: wordlist + 2-digit suffix
   hashcat -m <mode> -a 6 hashes.txt /usr/share/wordlists/rockyou.txt ?d?d
   # John format examples
   john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
   john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
   ```

   **Attack escalation ladder (mandatory):** Do not stop at a single dictionary pass. For each hash file, escalate through these stages in order until cracking reaches the agreed time budget: (1) dictionary with `best64.rule`, (2) dictionary with `dive.rule` or `OneRuleToRuleThemAll.rule`, (3) target-specific wordlist from `cewl` + company terms with rules, (4) mask attack matching the known password policy, (5) hybrid wordlist + mask append/prepend. If zero hashes crack after stage 1, first verify the hash type, mode, and format are correct.

   4b. **Encrypted file hash extraction**
   - Use `*2john` utilities to extract hashes from encrypted files before cracking:

   ```bash
   zip2john protected.zip > zip_hash.txt
   ssh2john id_rsa > ssh_hash.txt
   keepass2john database.kdbx > keepass_hash.txt
   gpg2john private.key > gpg_hash.txt
   rar2john archive.rar > rar_hash.txt
   ```

5. **Online testing**
   - Use `hydra`, `medusa`, `patator`, `crowbar`, `netexec`, or service-specific tools.
   - Use known credentials and default credentials before brute force.
   - Enforce lockout-safe delays, per-account attempt limits, and stop conditions.

   (See `../password/README.md` for online attack tool selection.)

   Online testing (respect lockout policy):
   - SSH/FTP/Web forms: `hydra -l <user> -P <wordlist> <protocol>://<target>` (see `../password/tools/hydra.md` for protocol-specific syntax)
   - SMB/WinRM credential testing: `nxc smb <cidr> -u <user> -p <pass>` (see `../password/tools/netexec.md`)
   - Kerberos password spraying: `kerbrute passwordspray -d <domain> --dc <dc-ip> valid_users.txt '<password>'` (see `../password/tools/kerbrute.md`)

   ```bash
   # Kerberos password spraying (lockout-safe: one password across many users)
   kerbrute passwordspray -d <domain> --dc <dc-ip> valid_users.txt 'Password1!'
   ```

   **Per-protocol online coverage:** Test ALL discovered authentication services (SSH, RDP, SMB, FTP, HTTP login, databases), not just one protocol. Use `netexec` for multi-protocol sweeps and `hydra` or `medusa` for protocol-specific depth. An untested service is an untested attack surface.

6. **Credential reuse**
   - Test cracked or provided credentials across authorized services only.
   - Record success, failure, MFA, disabled accounts, and permission level.

   (See `../password/README.md` for credential testing tool selection.)

   Test cracked credentials across services with `nxc` (see `../password/tools/netexec.md` for smb/winrm/mssql/ssh protocol modules).

   ```bash
   nxc smb <CIDR> -u cracked_users.txt -p cracked_passwords.txt --continue-on-success
   nxc winrm <CIDR> -u <user> -H <hash>
   nxc ssh <CIDR> -u <user> -p '<password>'
   nxc mssql <CIDR> -u <user> -p '<password>'
   ```

   **Credential × service coverage matrix (mandatory):** Test every cracked credential against every authorized service and protocol — not just one. Build a matrix of credentials × services (SMB, WinRM, SSH, RDP, MSSQL, LDAP, HTTP) and record each cell as: success, failure, MFA blocked, account disabled, or not tested. Untested cells are coverage gaps.

   6b. **MFA assessment** (risk gate: requires explicit approval)
   - Test for MFA fatigue: send repeated push notifications to determine if the user eventually approves.
   - Test OTP brute force on short codes (4-6 digits): check for rate limiting and lockout on verification endpoints.
   - Test backup code reuse: verify whether backup codes are invalidated after use.
   - Test MFA enrollment bypass: determine if an attacker with valid credentials can register their own MFA device without additional verification.
   - Document MFA coverage gaps — endpoints or flows that skip MFA enforcement.

7. **Hash capture**
   - Use `responder`, relay-related tools, or capture workflows only with explicit approval and internal scope.
   - Always start with analyze mode (`responder -A`) to observe traffic before active poisoning.

   (See `../password/README.md` for hash capture tool selection. See `../exploitation/README.md` for relay tool selection.)
   - For relay attacks, use `ntlmrelayx` to relay captured authentication to other services (see `../exploitation/tools/impacket.md`), and `mitm6` for IPv6-based MITM (see `../exploitation/tools/mitm6.md`).

   If authorized for internal LAN capture, run `responder -I <interface>` (see `../password/tools/responder.md`).

   ```bash
   # Step 1: analyze mode — observe without poisoning
   responder -I <interface> -A
   # Step 2: active poisoning (requires explicit approval)
   responder -I <interface>
   # NTLM relay to target services
   impacket-ntlmrelayx -tf targets.txt -smb2support
   # IPv6 MITM for WPAD/DNS takeover
   mitm6 -d <domain>
   ```

## Cross-References

- `active-directory.md` — AS-REP roasting and Kerberoasting attack workflows.
- `post-exploitation.md` — hash extraction methods.
- `reporting-workflow.md` — findings documentation.

## Expected Artifacts

- Hash type inventory.
- Wordlists/rules used.
- Cracking command logs and cracked credential list.
- Online attempt counts and lockout-safe evidence.
- Credential reuse matrix by service.

## Stop When

- Offline cracking reaches the agreed time budget.
- Online testing reaches the agreed attempt limit.
- Any account lockout risk, unexpected production impact, or out-of-scope credential appears.
