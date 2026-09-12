# zaproxy

- **Category**: Web / DAST Automation
- **Risk Level**: 🟡 Medium

---

## Description

OWASP ZAP (Zed Attack Proxy) is a web application security testing proxy and DAST scanner. Although it is commonly used with a GUI, the official project also supports command-line execution through `zap.sh` / `zaproxy`, daemon mode with API control, the Automation Framework (`-autorun` YAML plans), quick command-line scans, and official Docker packaged scan scripts (`zap-baseline.py`, `zap-full-scan.py`, `zap-api-scan.py`). For agent workflows, use ZAP for passive baseline scans, API definition scans, authenticated automation plans, and cross-validation alongside nuclei, nikto, and manual endpoint testing.

## Installation

```bash
sudo apt update
sudo apt install zaproxy

zaproxy -h
owasp-zap -h

# Optional: pull the official stable ZAP Docker image for packaged scans
docker pull ghcr.io/zaproxy/zaproxy:stable
```

## Parameter Reference

| Parameter | Description |
|---------------------|-------------|
| `zaproxy -h` | Show ZAP command-line options on Kali |
| `zaproxy -version` | Print the installed ZAP version |
| `-cmd` | Run inline and exit when command-line actions complete |
| `-daemon` | Start ZAP without the desktop UI |
| `-host <host>` | Bind the ZAP proxy/API listener to a host |
| `-port <port>` | Bind the ZAP proxy/API listener to a port |
| `-config key=value` | Override a ZAP configuration value |
| `-quickurl <url>` | Run a quick scan against a target URL |
| `-quickout <file>` | Write quick scan output; format follows file extension (`.html`, `.json`, `.md`, `.xml`) |
| `-autorun <file-or-url>` | Run an Automation Framework YAML plan |
| `-autogenmin <file>` | Generate a minimal automation template |
| `-autogenmax <file>` | Generate a full automation template |
| `-autocheck <file-or-url>` | Validate an automation plan without running it |
| `-openapiurl <url>` | Import an OpenAPI definition from a URL |
| `-openapifile <file>` | Import an OpenAPI definition from a file |
| `-graphqlurl <url>` | Import a GraphQL schema from a URL |
| `-addonupdate` | Update installed ZAP add-ons |
| `zap-baseline.py` | Official Docker packaged passive baseline scan |
| `zap-full-scan.py` | Official Docker packaged spider plus active scan |
| `zap-api-scan.py` | Official Docker packaged API scan for OpenAPI, SOAP, or GraphQL |

## Common Commands

### Local Kali CLI

```bash
# Version and help
zaproxy -version
zaproxy -h

# Quick scan and save HTML output
zaproxy -cmd \
  -quickurl https://target.com \
  -quickout /tmp/zap-quick.html

# Start ZAP as a headless daemon for browser/proxy/API-driven testing
zaproxy -daemon \
  -host 127.0.0.1 \
  -port 8080 \
  -config api.disablekey=true

# Confirm the API is reachable
curl "http://127.0.0.1:8080/JSON/core/view/version/"

# Generate and validate an Automation Framework plan
zaproxy -cmd -autogenmin /tmp/zap.yaml
zaproxy -cmd -autocheck /tmp/zap.yaml

# Run an Automation Framework plan
zaproxy -cmd -autorun /tmp/zap.yaml
```

### Official Docker Packaged Scans

```bash
# Passive baseline scan: suitable for CI/CD and production-safe checks
docker run -v "$(pwd)":/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://target.com -r zap-baseline.html -J zap-baseline.json

# Full scan: includes active scanning; use only with explicit authorization
docker run -v "$(pwd)":/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t https://target.com -r zap-full.html -J zap-full.json

# API scan from an OpenAPI definition
docker run -v "$(pwd)":/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t https://target.com/openapi.json -f openapi -r zap-api.html -J zap-api.json

# API scan against GraphQL endpoint
docker run -v "$(pwd)":/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t https://target.com/graphql -f graphql -r zap-graphql.html -J zap-graphql.json

# Run an Automation Framework plan with the official Docker image
docker run -v "$(pwd)":/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/zap.yaml
```

### Minimal Automation Plan

```yaml
env:
  contexts:
    - name: target
      urls:
        - https://target.com
jobs:
  - type: spider
    parameters:
      context: target
      maxDuration: 5
  - type: passiveScan-wait
    parameters:
      maxDuration: 10
  - type: report
    parameters:
      template: traditional-html
      reportDir: /tmp
      reportFile: zap-report.html
```

## Notes & Tips

1. Use `zap-baseline.py` first for low-impact passive checks; it spiders briefly and waits for passive scan results.
2. Treat `zap-full-scan.py` as an active attack scan. It can run for a long time and must stay within explicit authorization.
3. For APIs, prefer `zap-api-scan.py` with OpenAPI/SOAP/GraphQL definitions; it imports the API definition before scanning discovered endpoints.
4. For repeatable agent workflows, prefer `-autorun` Automation Framework YAML over ad hoc GUI steps.
5. If exposing the ZAP API beyond localhost, do not use `api.disablekey=true`; set an API key and restrict allowed addresses.
6. Save HTML and JSON reports into `/tmp/` or a mounted `/zap/wrk/` directory so the agent can retrieve and parse results.

---

## Official References

- [ZAP Command Line](https://www.zaproxy.org/docs/desktop/cmdline/)
- [ZAP Docker User Guide](https://www.zaproxy.org/docs/docker/about/)
- [ZAP Baseline Scan](https://www.zaproxy.org/docs/docker/baseline-scan/)
- [ZAP Full Scan](https://www.zaproxy.org/docs/docker/full-scan/)
- [ZAP API Scan](https://www.zaproxy.org/docs/docker/api-scan/)
- [ZAP Kali Package](https://www.kali.org/tools/zaproxy/)
