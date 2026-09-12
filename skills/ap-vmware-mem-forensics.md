---
name: vmware-mem-forensics
description: Use when analyzing vmem or vmdk dumps for creds/secrets.
---

# VMware Memory-Dump Forensics (reusable)

## Quick triage order (cheapest first)
1. **volatility3 hashdump** on the vmem — local SAM hashes. A local-account
   hash is often REUSED as a domain credential; test every one via PTH before
   deep analysis. This beat full string-analysis on a real engagement.
2. `windows.registry.lsadump` — DPAPI_SYSTEM + NL$KM (machine secrets).
3. `windows.cachedump` — cached domain logons (often empty on servers).
4. `windows.info/pslist` — confirm OS, find lsass PID.
5. `windows.svclist` / registry printkey — identify the machine's role
   (DC vs member workstation changes everything).

## String-search reality check
- ASCII + UTF-16LE `strings -el` both, 2M+ lines is normal.
- A person/account name NOT appearing as plaintext is COMMON — creds live in
  binary structures (hashes, DPAPI blobs, Kerberos tickets), not strings.
  Don't conclude 'not here' from string absence; go structural (step 1).
- Grep hits like random-personal-domain.biz = false positives; check context.

## Structural sweeps when hashes aren't enough
- DPAPI blobs: scan magic `01 00 00 00 d0 8c 9d df` (bytes pattern) — decrypt
  with dpapi_machinekey/userkey from lsadump.
- KRB-CRED carving: scan for ASN.1 0x76 (APPLICATION 6) + inner 0x30; carve
  by DER length. Encrypted ticket bodies are opaque — sname/realm only.
- mimikatz-pipe strings in memory = a dump TOOL ran on the box, not creds.

## vmdk handling
- Delta disk (`-000001.vmdk`) needs its parent (10GB base often too slow to
  pull) — convert: `qemu-img convert -O raw x.vmdk out.raw` (qemu-utils
  installed). Prefer vmem analysis over 10GB disk pulls.
- vmsn = snapshot metadata+memory; check `vmsd` for snapshot identity.

## Toolchain (this host)
- vol: `~/tools/volenv/bin/vol -q -f <vmem> <plugin>`
- Installed via `python3 -m venv ~/tools/volenv && pip install volatility3`
- lsassy plugin NOT registered in vol3 — use vol native plugins instead.
- 2GB vmem: each plugin run ~1-3 min; strings -el ~2 min. Budget accordingly.
