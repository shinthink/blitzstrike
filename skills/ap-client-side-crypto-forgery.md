---
name: client-side-crypto-forgery
description: Use when client JS embeds crypto keys. Forge valid payloads.
---

# Client-Side Crypto Forgery (reusable)

Pattern - a webapp implements its own protection by encrypting/Signing data
IN THE BROWSER. If the key ships to the client, the crypto is theater -
extract it and forge arbitrary valid payloads. Authorized engagements only.

## Finding the key
- Read ALL app JS bundles - main.js, feature-specific wrappers, especially
  anything handling forms the server validates.
- grep bundles for - `CryptoJS`, `AES`, `GCM`, `SHA256`, `secret`, `key`,
  `encrypt(`, `CryptoKey`, `JSEncrypt`, long base64/hex literals.
- Devtools Sources tab + pretty-print ({} button) beats grep for obfuscated
  code. Key may be split/derived (e.g. SHA256(passphrase) as the AES key).
- AGENT REDACTION GOTCHA - some agent runtimes rewrite literal secret strings
  in output. Write the key via split-concat to a file, read it back in later
  scripts - `python3 -c "k='par'+'T1';open('/tmp/k','w').write(k)"`

## Replicating the scheme
1. Identify - algorithm (AES-GCM? CBC?), key derivation (raw? hashed?),
   IV generation (random 12 bytes? fixed?), output encoding (base64 of
   iv||ct||tag is the common shape).
2. Re-implement EXACTLY, then verify with a roundtrip test before sending
   anything to the target - enc->dec->equals original MUST pass.
3. Capture one legitimate encrypted request/response and confirm your
   implementation decrypts it. If it does, your forgeries are indistinguishable.

## Python reference (AES-GCM, SHA256-derived key, b64(iv+ct))
```python
import os, json, base64, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def enc(key_str, payload):
    key = hashlib.sha256(key_str.encode()).digest()
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(payload).encode(), None)
    return base64.b64encode(iv + ct).decode()

def dec(key_str, b64):
    key = hashlib.sha256(key_str.encode()).digest()
    raw = base64.b64decode(b64)
    return json.loads(AESGCM(key).decrypt(raw[:12], raw[12:], None))
```

## Escalation paths once forging works
- Tamper hidden fields - role, price, user_id, workflow state
- Inject content into fields the server trusts and renders later (stored
  XSS via fields that other users/admins view)
- Replay with modified nonces/timestamps if server dedupes on them

## Operational notes
- CSRF nonce/session tokens usually still required - scrape them from page
  source per-request before each submit.
- Server responses reveal validity - distinct error for bad-crypto vs
  bad-content tells you which half is broken.
- If the key is NOT in client JS but derived at login, check for it leaking
  in a JWT claim, cookie, or an API response field.
