# whois

- **Category**: Information Gathering / OSINT
- **Risk Level**: 🟢 Low

---

## Description

whois is the most basic domain/IP registration information query tool. It retrieves domain registrant, registrar, DNS servers, IP range ownership, and other information by querying the WHOIS database. Purely passive query — will not be detected by the target.

## Installation

```bash
sudo apt install whois
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `domain/IP` | Query target (domain name or IP address) |
| `-h HOST` | Connect to specified WHOIS server |
| `-p PORT` | Connect to specified port (default 43) |
| `-I` | Query whois.iana.org and follow its referral |
| `-H` | Hide legal disclaimers (cleaner output for parsing) |
| `--verbose` | Explain what is being done |

## Common Commands

```bash
# Domain WHOIS
whois target.com

# IP WHOIS (get ASN and IP range ownership)
whois 8.8.8.8

# Query registrar information
whois target.com | grep -i "registrar\|name server\|expiry"

# Extract key information
whois target.com | grep -iE "registrant|admin|tech|email|phone|name server"

# Specify WHOIS server
whois -h whois.arin.net 192.0.2.1    # TEST-NET-1 (RFC 5737); replace with real IP for North America
whois -h whois.ripe.net 198.51.100.1 # TEST-NET-2 (RFC 5737); RIPE covers Europe/Middle East — use a real RIPE IP

# Batch queries (combined with shell loop)
for domain in target.com target2.com; do
  echo "=== $domain ==="; whois $domain | grep -i "registrant\|email"
done
```

### Key Information Extraction

```bash
# Extract email addresses (for spear phishing)
whois target.com | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

# Extract DNS servers
whois target.com | grep -i "name server"

# Extract registration dates
whois target.com | grep -i "creation\|updated\|expir"
```

## Notes & Tips
1. Some domains have WHOIS privacy protection enabled; information may be masked
2. Use in combination with theHarvester and amass for better results
3. IP queries can yield ASN, CIDR, and other internal network expansion information

---

## Official References

- [whois GitHub](https://github.com/rfc1036/whois)
- [RFC 3912 - WHOIS Protocol](https://www.rfc-editor.org/rfc/rfc3912)
