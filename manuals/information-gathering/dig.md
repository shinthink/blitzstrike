# dig

- **Category**: Information Gathering / DNS Reconnaissance
- **Risk Level**: 🟢 Low

---

## Description

dig (Domain Information Groper) is the most powerful DNS query tool, capable of querying various DNS record types. `host` is a simplified version; `nslookup` is the cross-platform universal version. DNS enumeration can expose subdomains, mail servers, internal hostnames, and other sensitive information.

## Installation

```bash
sudo apt install bind9-dnsutils
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `@server` | Specify DNS server |
| `name` | Domain name to query |
| `type` | Record type (A/MX/NS/TXT/AAAA/ANY, etc.) |
| `+short` | Show results only, without header information |
| `+noall +answer` | Show only the answer section |
| `+trace` | Trace the full DNS resolution path |
| `-x IP` | Shortcut for reverse lookups |
| `axfr` | Request zone transfer |

## Common Commands

```bash
# Basic A record query
dig target.com
dig target.com A

# Query all record types
dig target.com ANY

# Mail servers (MX)
dig target.com MX

# DNS servers (NS)
dig target.com NS

# TXT records (including SPF, DKIM, verification info)
dig target.com TXT

# AAAA (IPv6)
dig target.com AAAA

# Reverse lookup
dig -x 8.8.8.8

# Query using a specific DNS server
dig @8.8.8.8 target.com
dig @1.1.1.1 target.com MX

# Zone transfer attempt (high value!)
dig axfr @ns1.target.com target.com
dig axfr @ns2.target.com target.com

# Trace resolution path
dig +trace target.com

# Concise output
dig +short target.com
dig +noall +answer target.com MX

# host command (simplified version)
host target.com
host -t MX target.com
host -t NS target.com
host -l target.com ns1.target.com   # zone transfer
host 8.8.8.8                        # reverse lookup

# nslookup (interactive)
nslookup
> server 8.8.8.8
> set type=ANY
> target.com
> exit
```

### Zone Transfer

```bash
# 1. First get NS servers
dig target.com NS +short

# 2. Attempt zone transfer against each NS
dig axfr @ns1.target.com target.com
dig axfr @ns2.target.com target.com

# Success returns all DNS records, exposing all subdomains!
```

## Notes & Tips
1. Zone transfer on a misconfigured DNS server can yield a complete subdomain list
2. TXT records often contain SPF, DKIM, Google/AWS verification codes, and other sensitive information
3. Use with dnsenum and dnsrecon for more efficient automated enumeration

---

## Official References

- [BIND 9 dig Man Page](https://bind9.readthedocs.io/en/latest/manpages.html#dig)
