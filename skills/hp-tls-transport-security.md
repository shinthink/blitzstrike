---
name: tls-transport-security
description: Use when you need to check TLS/SSL configuration on a host — weak cipher suites, deprecated protocol versions (SSLv3/TLS 1.0/1.1), certificate chain issues, missing HSTS, and protocol downgrade risk.
---

# TLS / transport security

## Prerequisites

- `testssl.sh`, `sslyze`

## Workflow

1. **Full configuration scan:**
   ```bash
   testssl.sh --jsonfile findings/testssl.json https://target.example.com
   ```
   or the faster alternative:
   ```bash
   sslyze --json_out findings/sslyze.json target.example.com
   ```

2. **Check specifically for:**
   - Deprecated protocols still enabled: SSLv2, SSLv3, TLS 1.0, TLS 1.1 (should be TLS 1.2 minimum, ideally 1.3-only for new deployments)
   - Weak cipher suites: anything using RC4, DES/3DES, export-grade ciphers, or NULL encryption
   - Certificate validity: not expired, not self-signed (unless intentionally internal), correct hostname match, full chain (not just leaf cert) served
   - Key strength: RSA keys ≥ 2048 bits, or ECDSA in use
   - Known protocol-level vulnerabilities the tool flags directly: Heartbleed, POODLE, BEAST, CRIME, ROBOT, Logjam — testssl.sh checks all of these by default
   - `HSTS` header present with a reasonable `max-age`, and `includeSubDomains` if appropriate — absence means the app can't force HTTPS-only on repeat visits, opening a downgrade window

3. **Certificate transparency check** — search [crt.sh](https://crt.sh) for the domain to confirm no unexpected/rogue certificates have been issued for it by a misconfigured or compromised CA account.

## Output

`findings/testssl.json` or `findings/sslyze.json`. Report per finding: what's misconfigured, the specific protocol/cipher/cert issue, severity (protocol downgrade and known CVEs like Heartbleed are critical; missing HSTS alone is low-medium), fix (server/load-balancer TLS config change, cert reissuance).

## Notes

- This is a passive, read-only check against the TLS handshake — safe to run against production without coordination.
- Modern managed platforms (Cloudflare, most cloud load balancers, Let's Encrypt via a current ACME client) rarely have real findings here — a clean result is common and expected, not a sign the scan didn't work.
