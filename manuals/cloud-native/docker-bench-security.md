# docker-bench-security

- **Category**: Cloud-Native / Container Runtime Audit
- **Risk Level**: 🟢 Low

---

## Description

Checks a Docker host against Docker security best practices inspired by the CIS Docker Benchmark. It audits daemon configuration, containers, images, networking, logging, and Docker socket exposure.

## Installation

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-c <check>` | Run a specific check or section |
| `-e <check>` | Exclude a check |
| `-l <file>` | Log output file |
| `-u <users>` | Comma-delimited list of trusted Docker user(s) |
| `-i <include>` | Comma-delimited list of patterns within a container or image name to include in checks |
| `-x <exclude>` | Comma-delimited list of patterns within a container or image name to exclude from checks |
| `-t <label>` | Comma-delimited list of labels within a container or image to check |
| `-n <limit>` | In JSON output, limit the number of reported items per list (default: `0` = no limit) |
| `-p` | Print remediation measures (default: remediation is NOT printed) |
| `-b` | Do not print colors |
| `-h` | Help |

## Common Commands

```bash
# Run on a Docker host
sudo ./docker-bench-security.sh -l /tmp/docker-bench.log

# Containerized run with host mounts
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -v /etc:/etc:ro -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /usr/bin/runc:/usr/bin/runc:ro -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --label docker_bench_security docker/docker-bench-security
```

## Notes & Tips

1. Requires access to the Docker host, not just a normal application container.
2. Findings are configuration risks; validate business impact before assigning severity.
3. A mounted Docker socket is usually a high-impact escalation path.

---

## Official References

- [docker-bench-security GitHub](https://github.com/docker/docker-bench-security)

