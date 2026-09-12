# Schemathesis

- **Category**: Web / API Schema-Based Fuzzing
- **Risk Level**: 🔴 High

---

## Description

OpenAPI, GraphQL, and schema-based API testing tool that generates requests from an API schema and checks for crashes, schema violations, and unexpected responses. It is high risk because it actively fuzzes API inputs.

## Installation

```bash
pipx install schemathesis
```

## Parameter Reference

### Top-Level Commands

| Command | Description |
|------|------|
| `run <location>` | Run property-based API tests against a schema URL or file |
| `fuzz <location>` | Run continuous API fuzzing |

### `schemathesis run` Options

| Parameter | Description |
|------|------|
| `-u, --url <url>` | API base URL (required for file-based schemas) |
| `-w, --workers` | Number of concurrent workers for testing (auto, 1-64) |
| `--phases <list>` | Comma-separated list of test phases to run (examples, coverage, fuzzing, stateful) |
| `--suppress-health-check <list>` | Comma-separated list of health checks to disable (data_too_large, filter_too_much, too_slow, large_base_example, all) |
| `--wait-for-schema <seconds>` | Maximum duration in seconds to wait for the API schema to become available |
| `-c, --checks <list>` | Comma-separated list of checks to run (not_a_server_error, status_code_conformance, content_type_conformance, response_schema_conformance, negative_data_rejection, all, etc.) |
| `--exclude-checks <list>` | Comma-separated list of checks to skip |
| `-H, --header <NAME:VALUE>` | Add a custom HTTP header to all API requests |
| `-a, --auth <USER:PASS>` | Basic authentication for all API requests |
| `--rate-limit <limit/duration>` | Rate limit in `<limit>/<duration>` format (e.g., `100/m`) |
| `--proxy <url>` | Set the proxy for all network requests |
| `--request-timeout <seconds>` | Timeout for each network request |
| `--max-failures <n>` | Terminate after reaching specified number of failures |
| `--max-response-time <seconds>` | Maximum allowed API response time |
| `-m, --mode` | Test data generation mode (positive, negative, all) |
| `-n, --max-examples <n>` | Maximum number of test cases per API operation |
| `--seed <int>` | Random seed for reproducible test runs |
| `--report <format>` | Generate reports (junit, vcr, har, ndjson, allure) |
| `--report-dir <dir>` | Directory to store report files (default: schemathesis-report) |
| `--exclude-deprecated` | Skip deprecated operations |

## Common Commands

```bash
# Run OpenAPI tests with conservative limits
schemathesis run https://target/openapi.json --checks all --rate-limit 5/s --report har --report-dir /tmp/schemathesis

# Authenticated API test
schemathesis run ./openapi.json --url https://target -H "Authorization: Bearer <token>"

# Reduce generated cases for quick triage
schemathesis run ./openapi.json --url https://target --max-examples 20

# Run only coverage and fuzzing phases with 4 workers
schemathesis run https://target/openapi.json --phases coverage,fuzzing -w 4

# Wait for schema availability (useful in CI)
schemathesis run https://target/openapi.json --wait-for-schema 30
```

## Notes & Tips

1. Requires explicit approval for active fuzzing and data-modifying endpoints.
2. Prefer staging environments or read-only endpoints when possible.
3. Use lower rate limits and small example counts before expanding coverage.

---

## Official References

- [Schemathesis Documentation](https://schemathesis.readthedocs.io/)
- [Schemathesis GitHub](https://github.com/schemathesis/schemathesis)
