# websocat

- **Category**: Web / API WebSocket Testing
- **Risk Level**: 🟡 Medium

---

## Description

Command-line WebSocket client and relay tool. Use it to test WebSocket handshake authentication, message-level authorization, injection, replay, and concurrency behavior.

## Installation

```bash
# Download static binary (no Rust toolchain needed)
curl -sL https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl \
  -o /usr/local/bin/websocat && chmod +x /usr/local/bin/websocat

# Or from source (requires Rust):
cargo install --features=ssl websocat
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `ws://` / `wss://` | WebSocket URL |
| `-H <header>` | Add HTTP header |
| `-n` | Do not send WebSocket Close message on EOF |
| `-E` | Exit on EOF |
| `--ping-interval <sec>` | Send pings periodically |
| `-t` | Text mode |

## Common Commands

```bash
# Connect to a WebSocket
websocat ws://target/socket

# Authenticated WebSocket
websocat -H "Cookie: session=<value>" wss://target/socket

# Send one JSON message
echo '{"action":"ping"}' | websocat -n wss://target/socket

# Save responses
websocat wss://target/socket > /tmp/websocket.log
```

## Notes & Tips

1. Test both handshake-level auth and per-message authorization.
2. Capture representative messages with browser DevTools, ZAP, or mitmproxy before replaying.
3. Avoid state-changing messages unless authorized.

---

## Official References

- [websocat GitHub](https://github.com/vi/websocat)

