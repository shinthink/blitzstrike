---
name: multi-domain-ad-attacks
description: Use when attacking across AD domain trust boundaries.
---

# Cross-domain AD attack chains (forest root <-> child)

Techniques for engagements spanning two AD domains joined by a trust
(placeholders: <home.realm> = domain you hold creds in, <child.realm> =
target domain). Authorized lab/CTF ranges and owned environments only.

## Rung 0 — before anything
1. Measure BOTH clocks: kinit a valid account into a FRESH ccache, read the
   KDC-set start-time (first 4 bytes of the ccache time field = KDC epoch),
   diff vs local epoch. `kdestroy -A` first — a cached TGT from a persistent
   keyring can mask real skew.
2. Until synced, attack via NTLM (skew-immune): LDAPS:636 + NTLM bind, SMB
   NTLM. Plain LDAP:389 usually demands signing; LDAPS accepts NTLM. GSSAPI
   LDAP needs the DC's FQDN (SPN), not the IP.
3. Fixing skew on a member box needs root, but real TGTs will not validate
   locally while skewed (chicken-and-egg). Get root skew-free first: a DA
   can create a rogue user over LDAPS+NTLM -> kinit it -> pipe commands into
   bare `ksu` (the `-e` form hits NOT_AUTHORIZED without .k5login/.k5users)
   -> `date -s @<kdc-epoch>`.

## The cross-realm referral chain (works where forging fails)
1. TGT for the owned home-domain account.
2. Ask the HOME KDC for a referral TGT: SPN `krbtgt/<CHILD.REALM>`.
3. Present the referral TGT to the CHILD KDC for the target service SPN
   (e.g. HOST/<child-dc>) -> real service ticket.
4. Merge home TGT + child ST into ONE ccache; SMB kerberosLogin with
   useCache=True then authenticates cross-realm.

Pitfalls:
- impacket getST does NOT follow referrals — direct cross-realm SPN requests
  return KDC_ERR_WRONG_REALM everywhere. Request the referral TGT explicitly.
- Referral-TGT objects may come back as RAW BYTES on some paths — type-check
  before subscripting fields when probing.

## Verdicts — stop iterating, change lanes
- FORGED TICKETS ARE DEAD on hardened DCs (Server 2025 class): fresh ticketer
  golds (any PAC variant) get KDC_ERR_TGT_REVOKED even against local-domain
  services EVEN WITH a verified-correct krbtgt key (dump it fresh to confirm
  before concluding). Real-ticket paths only.
- ext Enterprise Admins is NOT local admin on child DCs: child
  Builtin\Administrators and child user-creation writes are denied across the
  trust, and ext\EA never surfaces as a child local-admin token.
- Cross-NC DCSync as the PARENT-domain admin against the child DC fails
  (BAD_DN / OBJ_NOT_FOUND) in every identity form — trust-filtered. A/B rule:
  run the identical sync against your OWN DC first; objs=1 there proves your
  marshalling is fine, so the child failure is the trust — move lanes.
- Flags don't persist across respawns; hashes usually do. Re-verify banked
  creds per spawn before redoing chains.

## Recon sweep (LDAP-readable with any DA, BOTH domains)
- Trust object: trustType (2 = intra-forest), direction, child domain SID.
- foreignSecurityPrincipals in BOTH domains: a foreign SID inside a home
  group = a named bridge account — resolve the RID in the child user list.
- adminCount=1 + complete group->member map both sides (child domains are
  often tiny — enumerate everything before attacking).
- Kerberoast/AS-REP scans per domain (AES-only KDCs usually kill both).
- ADCS: pKIEnrollmentService in the child Configuration NC; ESC1-shape scan
  (ENROLLEE_SUPPLIES_SUBJECT + auth EKU); CertEnroll share check; ESC8 relay
  coerce is the standard child-DA finisher.
- Child SYSVOL via cross-realm Kerberos is often default-policy-only; parent
  SYSVOL (SMB NTLM as DA) is the richer GPP/GPO ground.

## Depth (references/)
- `references/pivot-tooling.md` — shipping a working impacket/python stack to
  a compromised pivot host (interpreter matching, silent-exit trap, NTLM
  deps, non-tty gotchas).
