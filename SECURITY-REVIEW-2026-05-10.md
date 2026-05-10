# Security Review — 2026-05-10

**Repository:** VollcomDigital/monitoring-hetzner-k8s-boilerplate  
**Scan type:** At-rest security review (scheduled weekly)  
**Branch:** `main`

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 3     |
| MEDIUM   | 1     |

---

## Findings

### 1. [HIGH] Unauthenticated Prometheus & Loki Ingresses Expose Sensitive Data

**Location:** `kubernetes/monitoring/prometheus-ingress.yaml`, `kubernetes/monitoring/loki-ingress.yaml`, `helm/loki/values.yaml:4`

**Description:**  
Prometheus and Loki are exposed to the public internet via Ingress resources without any authentication mechanism. Neither ingress defines `nginx.ingress.kubernetes.io/auth-url`, `auth-type`, or basic-auth annotations. Loki compounds this with `auth_enabled: false` (disabling even application-level tenant authentication), making the entire log push and query API accessible to unauthenticated users.

**Impact:**  
- Full read access to all infrastructure metrics (Prometheus) revealing internal architecture, service names, pod counts, resource usage, and potentially sensitive labels.
- Full read/write access to all application logs (Loki) which may contain PII, tokens, stack traces, or internal communications.
- An attacker can push crafted logs to Loki to trigger false alerts or pollute audit trails.

**Attack Path:**
1. Attacker discovers the Prometheus/Loki hostname via DNS enumeration or certificate transparency logs.
2. Sends unauthenticated HTTPS requests to `https://<PROMETHEUS_HOST>/api/v1/query` or `https://<LOKI_HOST>/loki/api/v1/query_range`.
3. Extracts all cluster metrics or application logs without credentials.
4. Pushes malicious log entries via `POST /loki/api/v1/push` to trigger alerting rules or corrupt log integrity.

**Evidence:**
- `kubernetes/monitoring/prometheus-ingress.yaml` — no auth annotations
- `kubernetes/monitoring/loki-ingress.yaml` — no auth annotations
- `helm/loki/values.yaml:4` — `auth_enabled: false`

**Remediation:**  
Add nginx basic-auth or OAuth2-proxy annotations to both ingresses:

```yaml
annotations:
  nginx.ingress.kubernetes.io/auth-type: basic
  nginx.ingress.kubernetes.io/auth-secret: monitoring-basic-auth
  nginx.ingress.kubernetes.io/auth-realm: "Authentication Required"
```

Additionally, enable `auth_enabled: true` in Loki for defense-in-depth multi-tenancy.

---

### 2. [HIGH] SSH and Kubernetes API Default to 0.0.0.0/0 (Entire Internet)

**Location:** `terraform/variables.tf:121-131`

**Description:**  
The `ssh_allowed_cidrs` and `api_allowed_cidrs` variables default to `["0.0.0.0/0", "::/0"]`, exposing SSH (port 22) and the Kubernetes API (port 6443) to the entire internet on every deployment that doesn't explicitly override these values. The firewall module directly consumes these CIDRs without validation.

**Impact:**  
- SSH root access to all cluster nodes is reachable from any IP, making brute-force/credential-stuffing attacks feasible if SSH keys are weak or leaked.
- The Kubernetes API server is publicly accessible, allowing authentication attempts with leaked kubeconfigs, stolen bearer tokens, or exploitation of K8s API vulnerabilities.

**Attack Path:**
1. User deploys cluster without overriding `ssh_allowed_cidrs`/`api_allowed_cidrs` (the example file comments them out).
2. Ports 22 and 6443 are open globally per `terraform/modules/firewall/main.tf:9-21`.
3. Attacker scans Hetzner IP ranges for open port 22/6443.
4. Attempts SSH key brute-force on root or uses a leaked kubeconfig to access the K8s API.
5. Gains full cluster admin access.

**Evidence:**
- `terraform/variables.tf:124-125` — `default = ["0.0.0.0/0", "::/0"]`
- `terraform/variables.tf:130-131` — `default = ["0.0.0.0/0", "::/0"]`
- `terraform/modules/firewall/main.tf:9-14` — SSH rule uses `var.ssh_allowed_cidrs`
- `terraform/modules/firewall/main.tf:17-21` — API rule uses `var.api_allowed_cidrs`
- `terraform/terraform.tfvars.example:14-16` — hardening is commented out

**Remediation:**  
Remove overly permissive defaults. Require explicit CIDR specification:

```hcl
variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to SSH into nodes"
  type        = list(string)
  # No default — force users to specify their own IP ranges
}

variable "api_allowed_cidrs" {
  description = "CIDR blocks allowed to access Kubernetes API"
  type        = list(string)
  # No default — force users to specify their own IP ranges
}
```

At minimum, add a validation block that rejects `0.0.0.0/0`:

```hcl
validation {
  condition     = !contains(var.ssh_allowed_cidrs, "0.0.0.0/0")
  error_message = "SSH must not be open to the entire internet. Specify restrictive CIDRs."
}
```

---

### 3. [HIGH] Grafana Defaults to admin/admin Credentials on Public Ingress

**Location:** `scripts/deploy-monitoring.sh:75`

**Description:**  
The Grafana admin password defaults to `"admin"` when `GRAFANA_ADMIN_PASSWORD` is not set or empty. The `.env.example` shows `GRAFANA_ADMIN_PASSWORD=` (blank), meaning most users following the quickstart will deploy with the default credential. Grafana is exposed publicly via the `grafana-ingress.yaml`.

**Impact:**  
An attacker gains full Grafana admin access, can view all dashboards/metrics/logs, modify alerting, add malicious data sources, and use Grafana's data source proxy to perform SSRF against internal cluster services.

**Attack Path:**
1. Attacker discovers `grafana.example.com` hostname (or actual configured hostname) via DNS/CT logs.
2. Navigates to the publicly exposed Grafana instance.
3. Logs in with `admin`/`admin`.
4. Gains full admin control: views all metrics, queries Loki logs, adds attacker-controlled data sources, or uses SSRF via data source proxy to reach internal services (e.g., `http://kube-prometheus-stack-prometheus:9090`, `http://loki:3100`).

**Evidence:**
- `scripts/deploy-monitoring.sh:75` — `--set grafana.adminPassword="${GRAFANA_ADMIN_PASSWORD:-admin}"`
- `.env.example:10` — `GRAFANA_ADMIN_PASSWORD=` (empty)
- `kubernetes/monitoring/grafana-ingress.yaml` — publicly accessible ingress

**Remediation:**  
Generate a random password if none is provided and output it securely:

```bash
GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-$(openssl rand -base64 24)}"
echo "Grafana admin password: $GRAFANA_ADMIN_PASSWORD" > "$PROJECT_DIR/.grafana-admin-password"
chmod 600 "$PROJECT_DIR/.grafana-admin-password"
```

Add a validation check that blocks deployment with empty/default passwords:

```bash
if [[ "${GRAFANA_ADMIN_PASSWORD}" == "admin" || -z "${GRAFANA_ADMIN_PASSWORD}" ]]; then
  echo "ERROR: GRAFANA_ADMIN_PASSWORD must be set to a strong, non-default value."
  exit 1
fi
```

---

### 4. [MEDIUM] Kubeconfig Written World-Readable (0644) on Control Plane Node

**Location:** `terraform/cloud-init/control-plane.yaml.tftpl:34`

**Description:**  
The k3s configuration sets `write-kubeconfig-mode: "0644"`, making the cluster admin kubeconfig (`/etc/rancher/k3s/k3s.yaml`) readable by all users and processes on the control plane node. The k3s default is `0600`.

**Impact:**  
Any compromised pod, sidecar, or lower-privileged process that gains filesystem access to the control plane node can read the full cluster-admin kubeconfig and escalate to complete cluster control.

**Attack Path:**
1. Attacker exploits a vulnerability in any workload running on the control plane node (or achieves container escape).
2. Reads `/etc/rancher/k3s/k3s.yaml` (world-readable).
3. Obtains cluster-admin bearer token.
4. Achieves full Kubernetes API admin access from any network location.

**Evidence:**
- `terraform/cloud-init/control-plane.yaml.tftpl:34` — `write-kubeconfig-mode: "0644"`

**Remediation:**  
Change to the secure default:

```yaml
write-kubeconfig-mode: "0600"
```

The Terraform `null_resource.kubeconfig` provisioner already uses SSH (as root) to retrieve the kubeconfig, so this change has no functional impact on the deployment workflow.

---

## Slack Reporting

⚠️ **Slack reporting was not possible** — no `SLACK_WEBHOOK_URL` environment variable or Slack MCP tool is configured. To enable automated Slack reporting, add a Slack webhook URL as a secret in the Cursor Dashboard (Cloud Agents > Secrets) with the key `SLACK_WEBHOOK_URL`.
