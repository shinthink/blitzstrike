# Clairvoyance

- **Category**: Web / API GraphQL Schema Discovery
- **Risk Level**: 🟡 Medium

---

## Description

GraphQL schema recovery tool that can infer schema details even when introspection is disabled by probing fields, types, and suggestions. Use it for authorized GraphQL endpoints when schema documentation is unavailable.

## Installation

```bash
pipx install clairvoyance
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `<url>` | GraphQL endpoint URL (positional, required) |
| `-o <file>` / `--output` | Output file for recovered JSON schema (default: stdout) |
| `-w <file>` / `--wordlist` | Wordlist for field/type brute-forcing |
| `-wv` / `--validate` | Validate wordlist items match GraphQL name regex |
| `-H <header>` / `--header` | Add custom HTTP header (repeatable) |
| `-i <file>` / `--input-schema` | Input file containing JSON schema to supplement |
| `-d <document>` / `--document` | Start with this document (default `query { FUZZ }`) |
| `-c <n>` / `--concurrent-requests` | Number of concurrent requests |
| `-x <proxy>` / `--proxy` | Define a proxy for all requests |
| `-k` / `--no-ssl` | Disable SSL verification |
| `-m <n>` / `--max-retries` | How many retries when a request fails |
| `-b <factor>` / `--backoff` | Exponential backoff factor |
| `-p <profile>` / `--profile` | Select a speed profile (`fast` or `slow`; default `fast`) |
| `-v` / `--verbose` | Increase verbosity level (repeatable) |
| `--progress` | Enable progress bar |

## Common Commands

```bash
# Recover schema from GraphQL endpoint
clairvoyance -o /tmp/schema.json https://target/graphql

# With authorization header
clairvoyance -H "Authorization: Bearer <token>" -o /tmp/schema.json https://target/graphql

# Use a wordlist for brute-forcing with validation
clairvoyance -w /tmp/graphql_wordlist.txt -wv -o /tmp/schema.json https://target/graphql

# Slow profile for rate-limited targets (1 concurrent, 50 retries, backoff 2)
clairvoyance -p slow -o /tmp/schema.json https://target/graphql

# Use a proxy and supplemental input schema
clairvoyance -x http://127.0.0.1:8080 -i /tmp/partial.json -o /tmp/schema.json https://target/graphql

# Disable SSL verification with verbose output and progress bar
clairvoyance -k -v --progress -o /tmp/schema.json https://target/graphql
```

## Notes & Tips

1. Start with normal introspection first; use clairvoyance when introspection is disabled.
2. The `slow` profile sets 1 concurrent request, 50 retries, and backoff factor 2 — use it for rate-limited endpoints.
3. Schema probing can generate many requests. Confirm rate limits and authentication scope.
4. Feed recovered schema to ZAP API scan or manual GraphQL query testing.

---

## Official References

- [Clairvoyance GitHub](https://github.com/nikitastupin/clairvoyance)
