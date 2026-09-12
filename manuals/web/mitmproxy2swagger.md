# mitmproxy2swagger

- **Category**: Web / API Specification Recovery
- **Risk Level**: 🟢 Low

---

## Description

Converts captured HTTP traffic from mitmproxy flows or HAR files into an OpenAPI 3.0 specification. Use it to create an API schema for ZAP API scans, schemathesis, or manual endpoint review.

## Installation

```bash
pipx install mitmproxy2swagger
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-i`, `--input <file>` | Input mitmproxy dump file or HAR dump file (required) |
| `-o`, `--output <file>` | Output OpenAPI YAML file; new endpoints are appended if file exists (required) |
| `-p`, `--api-prefix <url>` | API base URL prefix (required) |
| `-e`, `--examples` | Include request/response examples (may expose sensitive data) |
| `-hd`, `--headers` | Include headers in the schema (may expose sensitive data) |
| `-f`, `--format {flow,har}` | Override input file format auto-detection |
| `-r`, `--param-regex <regex>` | Regex to match path parameters; matching segments become placeholders |
| `-s`, `--suppress-params` | Exclude paths with original parameter values; only output placeholder paths |

## Common Commands

```bash
# Convert mitmproxy flows to OpenAPI draft
mitmproxy2swagger -i flows.mitm -o /tmp/openapi.yaml -p https://target/api

# Include examples
mitmproxy2swagger -i traffic.har -o /tmp/openapi.yaml -p https://target/api -e

# Include headers in examples
mitmproxy2swagger -i traffic.har -o /tmp/openapi.yaml -p https://target/api -e -hd

# Explicitly specify HAR format and suppress raw param paths
mitmproxy2swagger -i traffic.har -o /tmp/openapi.yaml -p https://target/api -f har -s

# Use regex to parameterize UUID path segments
mitmproxy2swagger -i flows.mitm -o /tmp/openapi.yaml -p https://target/api \
  -r '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
```

## Notes & Tips

1. Review and clean generated specs before feeding them to fuzzers.
2. Capture authenticated traffic with consent; flows may contain secrets.
3. Pair with `mitmdump` and ZAP API scan for repeatable API testing.

---

## Official References

- [mitmproxy2swagger GitHub](https://github.com/alufers/mitmproxy2swagger)
