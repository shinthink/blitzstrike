# Cloud-Native Assessment Playbook

Use for authorized cloud accounts, Kubernetes clusters, container images, registries, deployment manifests, serverless functions, CI/CD pipelines, or Docker hosts.

## Inputs

- Cloud provider (AWS, Azure, GCP), accounts/projects/subscriptions, regions, and credential type.
- Assessment mode: read-only audit, compliance-only check, or full penetration test with exploitation.
- Kubernetes context, kubeconfig, namespaces, manifests, Helm charts, or image lists.
- Docker host or registry endpoints and allowed authentication method.
- Serverless function names, CI/CD repository URLs, and pipeline configuration paths.
- Compliance baseline (CIS, SOC 2, PCI-DSS), read-only requirements, and scan time windows.

## Workflow

1. **Scope, access, and provider identification**
   - Confirm the assessment boundary: which accounts, projects, subscriptions, clusters, registries, serverless functions, and CI/CD pipelines are in scope.
   - Confirm read-only versus administrative access and whether exploitation (e.g., privilege escalation, container escape) is authorized.
   - Record the assessor identity, credential type (IAM user, assumed role, service principal, service account key), and permission level before any scanning.

   (See `../cloud-native/README.md` for cloud-native tool selection.)

   Identify the cloud provider and select the primary toolchain:

   - **AWS** — Verify credentials with `aws sts get-caller-identity`. Use `prowler` for compliance checks and ScoutSuite (`scout`) for broad inventory. If exploitation is authorized, use `pacu` for privilege escalation testing.
   - **Azure** — Verify credentials with `az account show`. Use `prowler azure` or `scout azure`.
   - **GCP** — Verify credentials with `gcloud auth list` and `gcloud config get-value project`. Use `prowler gcp` or `scout gcp`.

   ```bash
   # AWS — confirm identity and region
   aws sts get-caller-identity
   aws configure get region

   # Azure — confirm subscription and identity
   az account show --output json
   az ad signed-in-user show

   # GCP — confirm project and identity
   gcloud auth list
   gcloud config get-value project
   gcloud projects get-iam-policy PROJECT_ID --format=json
   ```

   Decision tree:
   - If the assessment is read-only compliance only, proceed directly to Phase 2 with `prowler`/ScoutSuite (`scout`) and skip exploitation-oriented phases.
   - If full pentest is authorized, include Phases 6 and 7 and document any exploitation attempts.
   - If Kubernetes is out of scope, skip Phase 4; if containers are out of scope, skip Phase 5.

2. **IAM and identity assessment**
   - Enumerate all IAM users, roles, groups, and policies for the target account/project.
   - Identify over-permissive roles: look for `*` permissions, `iam:PassRole` without resource constraints, `sts:AssumeRole` with wide trust policies, or Azure roles with `Microsoft.Authorization/roleAssignments/write`.
   - Check for privilege escalation paths: roles that can create new roles, attach policies, or modify trust relationships.
   - Test service account and service principal permissions: verify least-privilege and check for unused or stale credentials.
   - Check federation, OIDC trust, and cross-account/cross-project trust relationships for overly broad configurations.

   ```bash
   # AWS — enumerate IAM
   aws iam list-users --output json > /tmp/iam_users.json
   aws iam list-roles --output json > /tmp/iam_roles.json
   aws iam list-policies --scope Local --output json > /tmp/iam_policies.json
   aws iam list-role-policies --role-name ROLE_NAME
   aws iam list-attached-role-policies --role-name ROLE_NAME
   aws iam get-policy-version --policy-arn POLICY_ARN --version-id v1

   # Azure — enumerate IAM
   az role assignment list --all --output json > /tmp/azure_roles.json
   az ad app list --output json > /tmp/azure_apps.json
   az ad sp list --all --output json > /tmp/azure_sps.json
   # Azure — BloodHound-style attack path enumeration (authenticate with an acquired JWT or refresh token)
   azurehound -j <jwt-token> list -o /tmp/azurehound.json

   # GCP — enumerate IAM
   gcloud projects get-iam-policy PROJECT_ID --format=json > /tmp/gcp_iam.json
   gcloud iam service-accounts list --format=json > /tmp/gcp_sa.json
   gcloud iam service-accounts keys list --iam-account SA_EMAIL

   # Prowler IAM-focused checks (AWS example)
   prowler aws --services iam --output-formats json-ocsf --output-directory /tmp/prowler_iam
   # ScoutSuite — review the IAM section of the generated report
   scout aws --report-dir /tmp/scoutsuite_report --no-browser
   ```

   For Kubernetes, test ServiceAccount permissions:

   ```bash
   # Check what the current ServiceAccount can do
   kubectl auth can-i --list
   # Check a specific ServiceAccount
   kubectl auth can-i --list --as=system:serviceaccount:NAMESPACE:SA_NAME
   # Look for cluster-admin bindings
   kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'
   ```

   See `../cloud-native/tools/prowler.md` and `../cloud-native/tools/scoutsuite.md` for full parameter reference. Use `azurehound` for Azure AD attack path enumeration similar to BloodHound (see `../cloud-native/tools/azurehound.md`).

   **Per-resource iteration (mandatory):** Do not spot-check one resource and extrapolate. For IAM: review the attached and inline policies of EVERY role, user, and service account. For storage: test ACLs on EVERY bucket/container. For compute: check security groups on EVERY instance. Use CLI loops to automate iteration over all enumerated resources.

   **Credential discovery handling:** When credentials are found during cloud enumeration (service account keys, access tokens in metadata, secrets in environment variables, storage bucket credentials, exposed .env files), immediately test them against all discovered cloud services and APIs before continuing to the next phase.

3. **Cloud infrastructure security**
   - Audit security groups / network ACLs (AWS), NSGs (Azure), or firewall rules (GCP) for overly permissive ingress — especially management ports (SSH/22, RDP/3389, database ports).
   - Enumerate storage resources (S3, Azure Blob, GCS) and test ACLs for public access or misconfigured policies.
   - Check for publicly exposed snapshots, AMIs, or VM images and unencrypted volumes.
   - Review logging and monitoring: CloudTrail, Azure Activity Log, or GCP Audit Log configuration.

   ```bash
   # AWS — security groups allowing 0.0.0.0/0 on sensitive ports
   aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?contains(IpRanges[].CidrIp, '0.0.0.0/0')]]" --output json > /tmp/open_sgs.json

   # AWS — S3 bucket ACLs and policies
   aws s3api list-buckets --output json > /tmp/buckets.json
   aws s3api get-bucket-acl --bucket BUCKET_NAME
   aws s3api get-bucket-policy --bucket BUCKET_NAME
   aws s3api get-public-access-block --bucket BUCKET_NAME

   # AWS — public snapshots and unencrypted EBS volumes
   aws ec2 describe-snapshots --owner-ids self --query "Snapshots[?CreateVolumePermissions[?Group=='all']]" --output json
   aws ec2 describe-volumes --query "Volumes[?!Encrypted].{ID:VolumeId,Size:Size}" --output table

   # Azure — NSG rules allowing any source
   az network nsg list --output json > /tmp/azure_nsgs.json
   az network nsg rule list --nsg-name NSG_NAME --resource-group RG_NAME --output json
   az storage account list --query "[?allowBlobPublicAccess==\`true\`]" --output json

   # GCP — firewall rules allowing 0.0.0.0/0
   gcloud compute firewall-rules list --filter="sourceRanges=0.0.0.0/0" --format=json > /tmp/gcp_fw.json
   gsutil iam get gs://BUCKET_NAME

   # Prowler — automated networking and storage checks
   prowler aws --services ec2 s3 vpc --output-formats json-ocsf --output-directory /tmp/prowler_infra
   ```

   Cross-reference with `internal-network.md` for deeper VPC network testing when authorized.

4. **Kubernetes cluster security**
   - Run CIS Kubernetes benchmark checks with `kube-bench` to identify node and cluster configuration gaps.
   - Use `kubescape` for RBAC analysis, network policy evaluation, exposure scanning, and framework compliance (NSA, MITRE ATT&CK).
   - Check for secrets stored in ConfigMaps or environment variables instead of Secret objects or external vaults.
   - Test network policies: verify that pods cannot reach unintended services or namespaces.
   - Evaluate pod security standards (PSS) or legacy PodSecurityPolicy enforcement.

   ```bash
   # kube-bench — CIS benchmark (run on node or via Job)
   kube-bench run --targets master,node --json > /tmp/kube_bench.json

   # kubescape — full framework scan
   kubescape scan framework nsa --format json --output /tmp/kubescape_nsa.json
   kubescape scan framework mitre --format json --output /tmp/kubescape_mitre.json
   # kubescape — RBAC analysis
   kubescape scan control C-0035 --format json --output /tmp/kubescape_rbac.json
   ```

   Check for misconfigurations in workloads:

   ```bash
   # Secrets in environment variables
   kubectl get pods --all-namespaces -o json | jq '.items[].spec.containers[].env[]? | select(.valueFrom.secretKeyRef != null or (.name | test("PASSWORD|SECRET|KEY|TOKEN"; "i")))'

   # Secrets in ConfigMaps
   kubectl get configmaps --all-namespaces -o json | jq '.items[] | select(.data | to_entries[] | .value | test("password|secret|key|token|apikey"; "i")) | {namespace: .metadata.namespace, name: .metadata.name}'

   # Namespaces without any network policy
   kubectl get namespaces -o json | jq -r '.items[].metadata.name' | while read ns; do
     count=$(kubectl get networkpolicies -n "$ns" --no-headers 2>/dev/null | wc -l)
     if [ "$count" -eq 0 ]; then echo "No NetworkPolicy: $ns"; fi
   done

   # Pod security — check for privileged pods
   kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | {namespace: .metadata.namespace, name: .metadata.name}'

   # Find containers with CAP_SYS_ADMIN
   kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.capabilities.add[]? == "SYS_ADMIN") | {namespace: .metadata.namespace, name: .metadata.name}'

   # Check pod security admission labels
   kubectl get namespaces -o json | jq '.items[] | {name: .metadata.name, labels: (.metadata.labels // {} | with_entries(select(.key | startswith("pod-security"))))}'
   ```

   See `../cloud-native/tools/kube-bench.md` and `../cloud-native/tools/kubescape.md` for full parameter reference. For authorized in-cluster exploitation, use `peirates` (see `../cloud-native/tools/peirates.md`). Risk gate: `peirates` performs active exploitation of Kubernetes service accounts and secrets — use only with explicit pentest authorization.

5. **Container and image security**
   - Scan container images for OS and application vulnerabilities, embedded secrets, and misconfigurations.
   - Check running containers for privileged mode, excessive capabilities, mounted host paths, and exposed `docker.sock`.
   - Test container escape vectors when exploitation is authorized (see Phase 4 for privileged-pod and capability queries).
   - Test registry authentication: anonymous pull access, credential enumeration, image overwrite permissions.

   ```bash
   # Trivy — scan a container image
   trivy image --severity HIGH,CRITICAL --format json -o /tmp/trivy_image.json IMAGE:TAG

   # Trivy — scan all images in a Kubernetes cluster
   kubectl get pods --all-namespaces -o json | jq -r '.items[].spec.containers[].image' | sort -u | while read img; do
     trivy image --severity HIGH,CRITICAL --format json -o "/tmp/trivy_$(echo $img | tr '/:' '__').json" "$img"
   done

   # Trivy — scan a filesystem or IaC
   trivy fs --scanners vuln,misconfig,secret --format json -o /tmp/trivy_fs.json /path/to/project

   # docker-bench-security — audit Docker host configuration
   cd /tmp && git clone https://github.com/docker/docker-bench-security.git && cd docker-bench-security
   sudo ./docker-bench-security.sh -l /tmp/docker-bench.log
   ```

   Check for host-path and `docker.sock` escape vectors (privileged-pod and `CAP_SYS_ADMIN` queries are in Phase 4):

   ```bash
   # Find containers with host path mounts
   kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.volumes[]? | .hostPath != null) | {ns: .metadata.namespace, pod: .metadata.name, hostPaths: [.spec.volumes[] | select(.hostPath != null) | .hostPath.path]}'

   # Find containers with docker.sock mounted
   kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.volumes[]? | .hostPath.path == "/var/run/docker.sock") | {ns: .metadata.namespace, pod: .metadata.name}'
   ```

   If container escape is authorized and vectors are found, cross-reference with `post-exploitation.md` for exploitation techniques.

   See `../vulnerability/tools/trivy.md` and `../cloud-native/tools/docker-bench-security.md` for full parameter reference.

6. **Serverless and CI/CD**
   - Review serverless function configurations: execution roles, environment variables, resource policies, and trigger sources.
   - Check for secrets in plaintext environment variables rather than secret managers.
   - Audit CI/CD pipeline configurations for secret exposure, insecure artifact handling, and overly permissive OIDC trust.

   ```bash
   # AWS Lambda — list functions and check environment variables / roles
   aws lambda list-functions --output json > /tmp/lambda_functions.json
   aws lambda get-function-configuration --function-name FUNCTION_NAME --query "Environment.Variables"
   aws lambda get-function-configuration --function-name FUNCTION_NAME --query "Role"
   aws lambda get-policy --function-name FUNCTION_NAME

   # Azure Functions — list function apps
   az functionapp list --output json > /tmp/azure_functions.json
   az functionapp config appsettings list --name APP_NAME --resource-group RG_NAME

   # GCP Cloud Functions — list functions
   gcloud functions list --format=json > /tmp/gcp_functions.json
   gcloud functions describe FUNCTION_NAME --format=json

   # Scan CI/CD configuration files for misconfigurations
   trivy config --severity HIGH,CRITICAL --format json -o /tmp/trivy_cicd.json /path/to/repo/.github/workflows/
   ```

   For CI/CD pipeline review, cross-reference with `source-code-audit.md` for IaC and configuration scanning of pipeline definition files.

7. **IMDS and cloud metadata**
   - Test Instance Metadata Service (IMDS) access from containers, pods, or VMs.
   - Check whether IMDSv2 (token-required) is enforced on AWS instances.
   - Test for SSRF paths that could reach the metadata endpoint.
   - Attempt credential harvesting from metadata to demonstrate impact.

   ```bash
   # AWS — test IMDS access (IMDSv1)
   curl -s http://169.254.169.254/latest/meta-data/
   curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
   curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

   # AWS — test IMDSv2 (token required)
   TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
   curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

   # AWS — check IMDSv2 enforcement on instances
   aws ec2 describe-instances --query "Reservations[].Instances[].{Id:InstanceId,IMDS:MetadataOptions}" --output json

   # Azure — test IMDS
   curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
   curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

   # GCP — test metadata
   curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
   curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/project/project-id
   ```

   If credentials are harvested from IMDS, document the scope of access they provide and the lack of enforcement controls. Do not use harvested credentials for lateral movement unless explicitly authorized.

8. **Validation, segmentation, and reporting**
   - Verify network segmentation between production/non-production, management planes, and data planes.
   - Re-check high-impact findings with provider-native CLI commands to rule out tool false positives.
   - Compile findings into categories:
     - **IAM and identity** — over-permissive roles, privilege escalation paths, stale credentials.
     - **Infrastructure** — exposed management ports, public storage, missing encryption.
     - **Kubernetes** — CIS benchmark failures, RBAC gaps, pod security violations.
     - **Container and image** — critical CVEs, escape vectors, registry exposure.
     - **Serverless and CI/CD** — plaintext secrets, overly permissive execution roles.
     - **Metadata** — IMDS exposure, credential harvesting.
   - Prioritize: exploitation-proven findings first, then confirmed misconfigurations, then informational.
   - Cross-reference with `reporting-workflow.md` for final documentation format and delivery.

   **Zero-findings verification:** When prowler or ScoutSuite report zero high/critical findings, do not accept without verification. Manually confirm at least: root/admin MFA is enabled, audit logging is active, encryption at rest is enforced on storage and databases, and no IAM users have console access with long-lived access keys. Document each manual verification step.

## Cross-References

- `internal-network.md` — VPC network testing.
- `post-exploitation.md` — container escape exploitation.
- `source-code-audit.md` — CI/CD pipeline and IaC review.
- `reporting-workflow.md` — findings documentation and delivery.

## Expected Artifacts

- Cloud account/project inventory with provider, regions, and credential scope.
- IAM enumeration results: users, roles, policies, privilege escalation paths, federation trusts.
- Infrastructure findings: security group/NSG/firewall audit, storage ACLs, public snapshot/AMI exposure.
- Kubernetes cluster reports: `kube-bench` CIS results, `kubescape` compliance, RBAC analysis.
- Container image vulnerability results, secret findings, escape vector documentation.
- Serverless function configuration audit and CI/CD pipeline security review.
- IMDS access test results and credential harvesting evidence.
- Consolidated findings report organized by category and severity with remediation priorities.

## Stop When

- All authorized accounts, clusters, images, registries, functions, pipelines, and hosts have been assessed.
- Further progress requires write privileges, remediation actions, or access to out-of-scope tenants.
- Exploitation attempts have been completed or are not authorized, and all findings have been documented.
