# Kubescape

- **Category**: Cloud-Native / Kubernetes Security
- **Risk Level**: 🟡 Medium

---

## Description

Open-source Kubernetes security platform providing comprehensive security coverage from development to runtime. Offers hardening, posture management, and runtime security capabilities including scanning cluster configurations, manifests, Helm charts, and CI artifacts. Supports frameworks such as NSA, MITRE ATT&CK, and CIS, with JSON output suitable for agent parsing. A CNCF incubating project.

## Installation

```bash
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `scan` | Run a scan |
| `framework <name>` | Scan against a framework |
| `control <id>` | Scan against a single control by ID (e.g., `C-0035`) |
| `--format json` | JSON output |
| `--output <file>` | Write output file |
| `--kubeconfig <file>` | Kubernetes config file |
| `<path>` | Manifest, directory, chart, or repository path |

## Common Commands

```bash
# Scan current cluster
kubescape scan framework nsa --format json --output /tmp/kubescape.json

# Scan Kubernetes manifests
kubescape scan ./k8s --format json --output /tmp/kubescape-manifests.json

# Scan with explicit kubeconfig
kubescape scan --kubeconfig <kubeconfig> --format json --output /tmp/kubescape.json
```

## Notes & Tips

1. Use manifest scanning when cluster credentials are not in scope.
2. Cluster scans require Kubernetes API access and may enumerate namespaces, workloads, RBAC, and secrets metadata.
3. Prefer JSON output for prioritizing failed controls and affected resources.

---

## Official References

- [Kubescape Documentation](https://kubescape.io/docs/)
- [Kubescape GitHub](https://github.com/kubescape/kubescape)

