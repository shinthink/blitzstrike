---
name: engagement-session-ops
description: Use when starting a CTF box or authorized engagement. Setup + gotchas.
---

# Engagement Session Ops — standard opening (reusable)

## Session start checklist (5 min)
1. VPN: `ip -br addr show tun0` — must have the lab tunnel IP. Dead → restart
   openvpn with the lab profile; VPN drops ~every 2h mid-session. Prefer TCP
   443 over UDP when both are offered (survives NAT).
2. Reachability: `ping -c2 <IP>`; TTL 127 = Windows, 64 = Linux.
3. **Confirm the CURRENT IP with the user** — lab machines change IP per
   spawn. Purge stale /etc/hosts entries (`sudo sed -i '/old-ip/d'
   /etc/hosts`), add fresh. NEVER resume from a prior session's IP without
   re-pinging: hour-long dead-target loops come from exactly this.
4. Workdir: one directory per target IP — ports.txt, SOLVED.md, exploit
   scripts, state files all live there.
5. Recon: `sudo nmap -Pn -sS -p- --min-rate 2000 -T4 <IP> -oN ports.txt`
   (root needed for SYN; fall back to -sT unprivileged).
6. Windows targets: clock-sync FIRST (see ad-ntds-escalation Rung 0).

## Tool inventory discipline
Before hunting for a tool mid-engagement, run a one-shot inventory of what
EXISTS on this host (see references/host-toolchain.md for a worked example
of the inventory format). Typical layout on a pentest-ready Linux box:
- nmap (SYN needs root; connect scan doesn't)
- impacket example scripts (find the venv/bin that has them)
- a hash-auth SMB/WinRM client (netexec/nxc or crackmapexec)
- bloodyAD or similar LDAP tool, volatility3 for memory work
- Wordlists: check /usr/share/wordlists AND user dirs before assuming

See `references/host-toolchain.md` for a concrete inventory from a real box
(useful as a template; paths differ per host — always verify live).

## Rules that prevent lost hours
- A probe returning nothing = 'not found HERE', never 'box is dead' — verify
  with a second vector (ping + TCP + nmap) before declaring anything.
- Background anything >3 min (NTDS dumps, 2GB+ file pulls) and poll the
  output file — foreground timeouts kill long runs mid-stream.
- Hosts file edits and clock changes need root — batch them into ONE command
  per turn, not scattered.
- State file per box: creds, chain, blockers — write it BEFORE stopping.
- Flags/credentials recovered are per-spawn for flags, often-stable for
  hashes — always TEST an old hash against a fresh spawn before redoing the
  chain from scratch.
- **C2/listener completeness**: any exfil listener must capture FULL requests
  INCLUDING POST bodies, not just headers/paths — a flag that arrives as a
  POST body is invisible to a header-only logger and looks like silence.
- **Assumptions die by callback**: 'service X is a mock / does not execute'
  must be proven with an out-of-band callback test before it becomes a
  stopping point. A trivial-payload test isolates platform-failure from
  payload-failure — run it before concluding anything.
- **Check writeups/history before declaring a path dead** — a search for
  public writeups on the target has rescued a 'blocked' engagement (root
  found in minutes after days of assuming closure).
