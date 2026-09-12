# mitmproxy

- **Category**: Web / Proxy Interception
- **Risk Level**: 🟡 Medium

---

## Description

mitmproxy is an official open-source intercepting proxy toolkit for HTTP/1, HTTP/2, HTTP/3, WebSockets, and other TLS-protected traffic. It provides three front ends: `mitmproxy` for an interactive terminal UI, `mitmweb` for a web UI, and `mitmdump` for non-interactive command-line capture, replay, filtering, and scripted traffic transformation. For agent workflows, `mitmdump` is the safest automation entry point: it can record flows, export HAR files, replay requests, run Python addons, and operate as a regular, reverse, SOCKS, or transparent proxy depending on the configured mode.

## Installation

```bash
sudo apt update
sudo apt install mitmproxy

mitmproxy --version
mitmdump --help
mitmweb --help
```

## Parameter Reference

| Parameter | Description |
|---------------------|-------------|
| `mitmproxy` | Interactive terminal proxy UI |
| `mitmdump` | Non-interactive CLI companion, suitable for automation |
| `mitmweb` | Web UI front end |
| `-p, --listen-port <port>` | Listen port for the proxy |
| `--listen-host <host>` | Bind address for the proxy |
| `-w <file>` | Write captured flows to a mitmproxy dump file |
| `-r <file>` | Read flows from a dump file |
| `-n, --no-server` | Do not start a proxy server; useful for offline flow processing or replay |
| `-s <script.py>` | Load a Python addon script |
| `--set key=value` | Set any mitmproxy option from the command line |
| `--mode regular` | Standard HTTP(S) proxy mode |
| `--mode reverse:<url>` | Reverse proxy mode in front of a target service |
| `--mode socks5` | SOCKS5 proxy mode |
| `--save-stream-file <file>` | Stream flows to a file as they arrive |
| `--set hardump=<file>` | Save a HAR file on exit |
| `--set ssl_insecure=true` | Do not verify upstream TLS certificates |
| `--set flow_detail=<0-4>` | Control mitmdump output verbosity |
| `-C <file>` | Replay client requests from a saved flow file |

## Common Commands

```bash
# Start a non-interactive HTTP(S) proxy on port 8080 and save all flows
mitmdump --listen-host 0.0.0.0 -p 8080 -w /tmp/flows.mitm

# Send a single curl request through the proxy
curl -x http://127.0.0.1:8080 -k https://target.com/

# Save a HAR file while capturing traffic
mitmdump -p 8080 \
  --set hardump=/tmp/traffic.har \
  -w /tmp/flows.mitm

# Read saved flows and show only POST requests
mitmdump -nr /tmp/flows.mitm "~m post"

# Filter saved flows and write matches to a new file
mitmdump -nr /tmp/flows.mitm -w /tmp/post-only.mitm "~m post"

# Replay all captured client requests
mitmdump -nC /tmp/flows.mitm -w /tmp/replay-result.mitm

# Run a Python addon to modify or inspect traffic
mitmdump -p 8080 -s /tmp/addon.py -w /tmp/scripted.mitm

# Reverse proxy mode in front of a target service
mitmdump --mode reverse:https://target.com \
  --listen-host 0.0.0.0 \
  --listen-port 8081 \
  -w /tmp/reverse-proxy.mitm

# SOCKS5 proxy mode
mitmdump --mode socks5 --listen-host 127.0.0.1 --listen-port 1080
```

### Signing Proxy Addon

When every request must carry a computed signature (e.g. HMAC, timestamp+nonce), use a `mitmdump` addon as a transparent signing layer so proxy-compatible tools work without per-tool signing code:

```python
# /tmp/sign_addon.py — adapt algorithm and headers to the target
import hashlib, time, uuid
from mitmproxy import http

def request(flow: http.HTTPFlow):
    ts = str(int(time.time()))
    rid = str(uuid.uuid4())
    url = flow.request.pretty_url
    sig = hashlib.sha1(f"{url} {ts} {rid}".encode()).hexdigest()
    flow.request.headers["X-Timestamp"] = ts
    flow.request.headers["X-Request-Id"] = rid
    flow.request.headers["X-Signature"] = sig
    flow.request.headers["Cookie"] = "session_token=TOKEN"
```

```bash
mitmdump -s /tmp/sign_addon.py --listen-port 8080 --set ssl_insecure=true --set http2=false &
```

Force `--set http2=false` when the target API validates mixed-case custom headers (e.g. `X-Signature`) — HTTP/2 mandates lowercase headers and mitmproxy enforces this, breaking server-side signature verification.

Tools that do not work through the signing proxy (see Notes & Tips #8) should inject auth headers directly via their own header flags, using a pre-computed token from a standalone login script.

```bash
sqlmap -u "https://api.example.com/v3/users/1" \
  --proxy=http://127.0.0.1:8080 --level=5 --risk=3

ffuf -u "https://api.example.com/v3/FUZZ" \
  -x http://127.0.0.1:8080 -w /usr/share/wordlists/api-routes.txt

dalfox url "https://api.example.com/v3/users/self" \
  --proxy http://127.0.0.1:8080
```

If login requires encryption (e.g. AES+RSA hybrid), write a standalone script to obtain the session token first, then hard-code it into the addon's header injection.

## Notes & Tips

1. Use `mitmdump` instead of the interactive `mitmproxy` UI for unattended agent runs.
2. Clients must trust the mitmproxy CA certificate for TLS interception; browse to `http://mitm.it` through the proxy to install it in interactive test setups.
3. Use `-w` for native flow capture and `--set hardump=...` when a standard HAR file is needed for reporting or external tools.
4. Use filters such as `~m post`, `~u regex`, and `~d domain` to reduce large captures before analysis.
5. Use `--mode reverse:<url>` when the client cannot be configured to use an HTTP proxy but can be pointed at the proxy listener.
6. Interception and replay can modify traffic and trigger actions on the target; keep it inside authorized scope.
7. When routing sqlmap through a signing addon, per-request timestamp changes destabilize time-based blind injection baselines — either hardcode a fixed timestamp in the addon during time-based tests, or tell sqlmap to skip time-based technique with `--technique=BEUS`.
8. **Proxy-incompatible tools**: nikto aborts when it detects a MITM certificate chain (TLS fingerprinting). For such tools, bypass the proxy entirely and inject auth headers directly via the tool's own header flags using a pre-obtained token.

---

## Official References

- [mitmproxy Documentation](https://docs.mitmproxy.org/stable/)
- [mitmproxy Getting Started](https://docs.mitmproxy.org/stable/overview/getting-started/)
- [mitmproxy Options](https://docs.mitmproxy.org/stable/concepts/options/)
- [mitmproxy Proxy Modes](https://docs.mitmproxy.org/stable/concepts/modes/)
- [mitmproxy Kali Package](https://www.kali.org/tools/mitmproxy/)
