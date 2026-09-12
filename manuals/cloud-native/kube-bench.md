# kube-bench

- **Category**: Cloud-Native / Kubernetes Compliance
- **Risk Level**: 🟢 Low

---

## Description

Checks Kubernetes nodes and cluster configuration against the CIS Kubernetes Benchmark. Best used with shell access to cluster nodes or a configured Kubernetes environment.

## Installation

```bash
# Containerized run is the most portable option
docker run --rm -v `pwd`:/host aquasec/kube-bench:latest --version
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `--json` | Output JSON |
| `--benchmark <name>` | Benchmark profile/version |
| `--version <version>` | Manually specify Kubernetes version |
| `run --targets <list>` | Restrict checks, such as `master,node,etcd,policies` |
| `-c, --check <id>` | Run one or more comma-delimited check IDs |
| `--group <id>` | Run all checks in one or more comma-delimited groups |
| `--skip <id>` | Skip one or more comma-delimited checks or groups |
| `--outputfile <file>` | Write JSON or JUnit output to a file |

## Common Commands

```bash
# Run all applicable checks and save JSON
kube-bench --json > /tmp/kube-bench.json

# Run node checks only
kube-bench run --targets node --json > /tmp/kube-bench-node.json

# Run selected checks
kube-bench --check "1.1.1,1.1.2" --json --outputfile /tmp/kube-bench-selected.json

# Containerized run on a node
docker run --rm --pid=host -v /etc:/etc:ro -v /var:/var:ro aquasec/kube-bench:latest --json
```

## Notes & Tips

1. `kube-bench` is a compliance audit, not an exploit scanner.
2. Many checks require node filesystem access; remote unauthenticated scans are not the expected workflow.
3. Report failed checks with context and remediation, not as exploitable vulnerabilities by default.

---

## Official References

- [kube-bench GitHub](https://github.com/aquasecurity/kube-bench)
