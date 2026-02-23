# KlusterShield — NIST SP 800-218 (SSDF) Control Mapping

This document maps every KlusterShield check and resource to its corresponding
NIST SP 800-218 Secure Software Development Framework (SSDF) practice.

NIST SP 800-218 is organized into four practice groups:

| Group | Name | Focus |
|---|---|---|
| **PO** | Prepare the Organization | Security governance, toolchain controls |
| **PS** | Protect the Software | Access controls, vulnerability management |
| **PW** | Produce Well-Secured Software | Secure coding, dependency management |
| **RV** | Respond to Vulnerabilities | Detection, remediation, disclosure |

KlusterShield also maps relevant checks to **DS** and **PV** from NIST SP 800-53.

---

## PO — Prepare the Organization

### PO.1.1 — Security requirements defined and communicated

**What KlusterShield does:**
- Enforces PodSecurityAdmission labels at namespace creation
- Labels all managed resources with compliance profile references
- Documents control coverage in every resource annotation

**Kubernetes resources:**
- Namespace labels (`pod-security.kubernetes.io/enforce: restricted`)
- Resource annotations (`klustershield/nist-controls`)

**Scanner check:** `_check_pod_security_admission()`

---

### PO.3.2 — Implement toolchain security controls

**What KlusterShield does:**
- Verifies NetworkPolicies exist in all managed namespaces
- Ensures OPA Gatekeeper is installed and constraints are active
- Validates that RBAC is explicitly defined

**Scanner check:** `_check_network_policies_exist()`

---

## PS — Protect the Software

### PS.1.1 — Store and transmit software securely

**What KlusterShield does:**
- Blocks privileged containers via OPA Gatekeeper at admission time
- Rejects containers that would expose the host kernel

**Gatekeeper template:** `manifests/gatekeeper/no-privileged-containers.yaml`  
**Scanner check:** `_check_no_privileged_containers()`

---

### PS.2.1 — Provide mechanisms to verify integrity

**What KlusterShield does:**
- Checks that containers do not run as root (`runAsNonRoot: true`)
- Validates container security contexts are explicitly defined

**Scanner check:** `_check_no_root_containers()`

---

## PW — Produce Well-Secured Software

### PW.4.1 — Adhere to secure coding practices

**What KlusterShield does:**
- Enforces resource limits on all containers (CPU + memory)
- Installs LimitRange to set namespace-wide defaults
- Prevents unbounded resource consumption that could affect other workloads

**Kubernetes resource:** `LimitRange: klustershield-limits`  
**Scanner check:** `_check_resource_limits()`

---

### PW.7.2 — Review and/or analyze human-readable code

**What KlusterShield does:**
- Checks for read-only root filesystems (`readOnlyRootFilesystem: true`)
- Prevents runtime filesystem modification that could indicate compromise

**Scanner check:** `_check_readonly_root_fs()`

---

## RV — Respond to Vulnerabilities

### RV.1.3 — Track and address vulnerabilities in all components

**What KlusterShield does:**
- Detects unpinned `:latest` image tags that prevent reproducible deployments
- Requires all images to use specific version or digest tags

**Scanner check:** `_check_no_latest_tags()`

---

### RV.3.3 — Analyze vulnerabilities to classify and prioritize remediation

**What KlusterShield does:**
- Detects pods with `hostPID: true` or `hostNetwork: true`
- These grant access to the host operating system and undermine container isolation

**Scanner check:** `_check_host_namespaces()`

---

## DS — Distribute Securely (NIST 800-53)

### DS.1.1 — Protect data at rest and in transit

**What KlusterShield does:**
- Provisions default-deny NetworkPolicy as baseline for every namespace
- Allows only explicitly permitted traffic (zero-trust model)
- DNS egress is the only automatic exception

**Kubernetes resource:** `NetworkPolicy: default-deny-all`  
**Scanner check:** `_check_default_deny_policy()`

---

### DS.2.1 — Control access to software and its configuration

**What KlusterShield does:**
- Detects secrets exposed as plain environment variables
- Recommends mounting secrets as volumes instead
- Creates least-privilege RBAC roles (viewer + editor)

**Kubernetes resources:** `Role: klustershield-viewer`, `Role: klustershield-editor`  
**Scanner check:** `_check_secrets_not_in_env()`

---

## PV — Verify (NIST 800-53)

### PV.1.1 — Test executable code to identify vulnerabilities

**What KlusterShield does:**
- Verifies explicit RBAC roles exist in managed namespaces
- Ensures namespaces are not relying solely on ClusterRoles

**Scanner check:** `_check_rbac_configured()`

---

### PV.1.2 — Configure environments to minimize attack surface

**What KlusterShield does:**
- Checks for `automountServiceAccountToken: false` on pods
- Reduces blast radius if a pod is compromised

**Scanner check:** `_check_service_account_tokens()`

---

## Compliance Score Calculation

KlusterShield uses a severity-weighted scoring model:

| Severity | Weight |
|---|---|
| Critical | 4 |
| High | 3 |
| Medium | 2 |
| Low | 1 |

```
Score = (sum of weights for PASS checks) / (sum of weights for all non-SKIP checks) × 100
```

A score of 80%+ is considered the minimum threshold for production readiness.
Use `--fail-below 80` to enforce this in CI/CD pipelines.
