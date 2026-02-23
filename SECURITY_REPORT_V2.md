# KlusterShield Security Vulnerability Report — Re-scan

**Project:** KlusterShield v0.1.0
**Language:** Python 3.11+
**Scan Date:** 2026-02-21
**Auditor:** Claude Code Static Analysis
**Previous Report:** `SECURITY_REPORT.md`
**Scope:** Full source — `klustershield/`, `scripts/`, `manifests/`, `requirements.txt`, `pyproject.toml`

---

## Re-scan Summary

This report reflects a full re-scan of the codebase after the changes applied since the original `SECURITY_REPORT.md`. All 15 original findings were resolved. 8 new or residual findings remain.

### Resolved Since Last Scan

| Original ID | Finding | Status |
|---|---|---|
| CRITICAL-1 | Command injection via f-string shell interpolation | ✅ Fixed |
| CRITICAL-2 | `StrictHostKeyChecking=no` SSH MITM | ✅ Fixed |
| HIGH-3 | XSS in HTML reports | ✅ Fixed |
| HIGH-4 | Path traversal in `--output` | ✅ Fixed |
| HIGH-5 | Proxmox password exposed via CLI arg | ✅ Fixed |
| HIGH-6 | `initContainers`/`ephemeralContainers` not scanned | ✅ Fixed |
| HIGH-7 | PSA `enforce-version: latest` unpinned | ✅ Fixed |
| MEDIUM-8 | Operator precedence bug in `_check_resource_limits` | ✅ Fixed |
| MEDIUM-9 | Silent exception swallowing inflating compliance score | ✅ Fixed |
| MEDIUM-10 | Dead code `pod_selector == {}` | ✅ Fixed |
| MEDIUM-11 | No input validation on `--namespace`/`--team` | ✅ Fixed |
| LOW-12 | Deprecated `datetime.utcnow()` | ✅ Fixed |
| LOW-13 | Jinja2 unused, XSS protection bypassed | ✅ Fixed |
| LOW-14 | Dev deps mixed into production `requirements.txt` | ✅ Fixed |
| LOW-15 | Missing `enforcer`/`auditor` modules — crash on use | ✅ Fixed |

---

## Current Severity Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 1 |
| 🟡 MEDIUM | 4 |
| 🔵 LOW | 3 |
| **Total** | **8** |

---

## Findings

---

### 🟠 HIGH-1 — Residual Shell-String Injection Surface in `exec_command`

**File:** `scripts/provision_cluster.py`, lines 167–176, 210–215
**CWE:** [CWE-78 — OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
**NIST 800-218:** PS.1.1, PS.2.1
**Status:** Residual (partially mitigated from CRITICAL-1)

#### Description

The command injection from the original report was significantly hardened with `validate_k3s_version()`, `validate_token()`, `validate_ip()`, and `shlex.quote()`. However, both `install_k3s_control_plane` and `install_k3s_worker` still build a **single shell string** that is passed to `paramiko.exec_command()`:

```python
# provision_cluster.py:167
install_cmd = (
    "curl -sfL https://get.k3s.io | "
    f"INSTALL_K3S_VERSION={safe_version} "
    "sh -s - server ..."
)
run_remote(ip, ssh_user, ssh_key, known_hosts, install_cmd)

# run_remote:145
_, stdout, stderr = client.exec_command(command, timeout=300)
```

Paramiko's `exec_command` invokes `/bin/sh -c <string>` on the remote host when passed a string. If any future relaxation of the regex validators occurs, or if an edge case exists in `shlex.quote()` output for the `+k3s` suffix characters, the underlying shell execution model still applies. The injection defense is currently `shlex.quote()` + regex — but the shell is still present in the execution chain.

#### Remediation

1. **Avoid shell pipelines altogether.** Instead of piping `curl` output to `sh`, download the install script to a temp file first, then execute it as a separate non-shell command:
   ```python
   # Step 1: download the script
   client.exec_command("curl -sfL https://get.k3s.io -o /tmp/k3s-install.sh && chmod +x /tmp/k3s-install.sh")
   # Step 2: execute with env vars set explicitly (no shell pipeline)
   client.exec_command(
       f"INSTALL_K3S_VERSION={safe_version} /tmp/k3s-install.sh server --disable traefik ..."
   )
   ```
2. **Document the shell-execution model** with a comment so future maintainers don't relax validators without understanding the risk.
3. **Consider a structural regex** for the k3s token format (see LOW-8) to further constrain the injection surface.

---

### 🟡 MEDIUM-2 — `_check_no_latest_tags` Does Not Use `_all_containers`

**File:** `klustershield/scanner/engine.py`, lines 596–602
**CWE:** [CWE-1254 — Incorrect Comparison Logic Granularity](https://cwe.mitre.org/data/definitions/1254.html)
**NIST 800-218:** RV.1.3
**Status:** New

#### Description

All other container-level checks were updated to use the `_all_containers()` helper that includes `init_containers` and `ephemeral_containers`, but `_check_no_latest_tags` was missed and still iterates only `p.spec.containers`:

```python
latest_images = [
    f"{p.metadata.namespace}/{p.metadata.name}: {c.image}"
    for p in pods
    for c in (p.spec.containers or [])   # ← should be self._all_containers(p)
    if c.image and (c.image.endswith(":latest") or ":" not in c.image)
    and not p.metadata.namespace.startswith("kube-")
]
```

A workload that uses a pinned image tag for its main container but a `:latest` tag in an `initContainer` will pass this check. This is a compliance gap against NIST RV.1.3 (pinned image tags).

#### Remediation

Replace the inner iteration with the existing `_all_containers()` helper, consistent with every other check in the file:

```python
for c in self._all_containers(p)
```

---

### 🟡 MEDIUM-3 — `hostIPC` Not Checked in Host Namespace Scan

**File:** `klustershield/scanner/engine.py`, lines 625–629
**CWE:** [CWE-269 — Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
**NIST 800-218:** RV.3.3
**Status:** New

#### Description

The `_check_host_namespaces` check covers `hostPID` and `hostNetwork` but omits `hostIPC`:

```python
violations = [
    f"{p.metadata.namespace}/{p.metadata.name}"
    for p in pods
    if (p.spec.host_pid or p.spec.host_network)   # ← p.spec.host_ipc missing
    and not p.metadata.namespace.startswith("kube-")
]
```

`hostIPC: true` grants a pod full access to the host's IPC namespace, enabling shared memory segments and semaphores with host processes. This is a well-known container escape and lateral movement primitive. NIST RV.3.3 concerns isolation from host resources broadly and should cover all three host namespace types.

#### Remediation

Add `host_ipc` to the condition and update the check's `title`, `description`, and `remediation` fields accordingly:

```python
if (p.spec.host_pid or p.spec.host_network or p.spec.host_ipc)
```

```python
check.remediation = "Set spec.hostPID: false, spec.hostNetwork: false, and spec.hostIPC: false"
```

---

### 🟡 MEDIUM-4 — `ns.metadata.labels` Can Be `None` — `AttributeError` in PSA Check

**File:** `klustershield/scanner/engine.py`, lines 428–433
**CWE:** [CWE-476 — NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
**NIST 800-218:** PO.1.1
**Status:** New

#### Description

The `_check_pod_security_admission` check calls `.get()` directly on `ns.metadata.labels` without guarding against `None`:

```python
missing = [
    ns.metadata.name
    for ns in namespaces
    if ns.metadata.labels.get("pod-security.kubernetes.io/enforce") != "restricted"
    and not ns.metadata.name.startswith("kube-")
]
```

For namespaces with no labels set at all (common in freshly created namespaces), `ns.metadata.labels` is `None`. Calling `.get()` on `None` raises `AttributeError`. This bubbles up through the `except Exception` handler, increments `error_count`, and produces a `SKIP` — meaning a namespace with **no labels at all** (and therefore definitely no PSA enforcement) is silently skipped rather than correctly flagged as `FAIL`.

#### Remediation

Guard with an `or {}` fallback before calling `.get()`:

```python
missing = [
    ns.metadata.name
    for ns in namespaces
    if (ns.metadata.labels or {}).get("pod-security.kubernetes.io/enforce") != "restricted"
    and not ns.metadata.name.startswith("kube-")
]
```

---

### 🟡 MEDIUM-5 — kubeconfig Written Without Restrictive File Permissions

**File:** `scripts/provision_cluster.py` — `fetch_kubeconfig()` / `--kubeconfig-out`
**CWE:** [CWE-732 — Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
**NIST 800-218:** DS.2.1, PV.1.1
**Status:** New

#### Description

`fetch_kubeconfig()` returns the kubeconfig as a string, and it is intended to be written to disk at `--kubeconfig-out` (default: `./kubeconfig.yaml`). Python's `Path.write_text()` creates files using the process's `umask`-derived permissions — typically `0o644` (owner read/write, group and world read) on most Linux systems. A world-readable kubeconfig grants **any local user on the machine full cluster access**, since k3s kubeconfigs typically contain `cluster-admin` credentials.

While the current `main()` scaffolding uses a placeholder and does not yet call `fetch_kubeconfig()` directly, the pattern will be insecure when wired up.

#### Remediation

After writing the kubeconfig, immediately restrict permissions to owner-only:

```python
import os
from pathlib import Path

kubeconfig_path = Path(kubeconfig_out)
kubeconfig_path.write_text(kubeconfig_content, encoding="utf-8")
os.chmod(kubeconfig_path, 0o600)
```

To avoid a TOCTOU race entirely, use `os.open()` with `O_CREAT | O_WRONLY` and `mode=0o600` before writing:

```python
fd = os.open(kubeconfig_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(kubeconfig_content)
```

---

### 🔵 LOW-6 — Path Traversal Guard Fragile When CWD Is `/`

**File:** `klustershield/scanner/engine.py`, lines 326–329
**CWE:** [CWE-22 — Improper Limitation of a Pathname](https://cwe.mitre.org/data/definitions/22.html)
**Status:** New (partially mitigated from HIGH-4)

#### Description

The `_resolve_output_path` guard checks:

```python
if safe_base not in candidate.parents:
    raise ValueError(
        f"Output path must be within current working directory: {safe_base}"
    )
```

`Path.parents` is a sequence of all ancestor directories up to the root. If the tool is run from a container or chroot where `cwd` resolves to `/`, then `safe_base = Path("/")` — and `/` appears in the `.parents` of **every** absolute path. In that scenario the guard passes for any path, defeating the path traversal protection entirely.

#### Remediation

Replace the `in parents` check with a `startswith` string comparison that requires the candidate to be strictly inside the base directory:

```python
if not str(candidate).startswith(str(safe_base) + os.sep):
    raise ValueError(
        f"Output path must be within current working directory: {safe_base}"
    )
```

Also add an explicit check that `safe_base` is not the filesystem root:

```python
if safe_base == Path("/"):
    raise ValueError("Refusing to write output when running from filesystem root.")
```

---

### 🔵 LOW-7 — Paramiko `exec_command` Timeout Is Socket-Level Only

**File:** `scripts/provision_cluster.py`, line 145
**CWE:** [CWE-400 — Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
**Status:** Residual

#### Description

```python
_, stdout, stderr = client.exec_command(command, timeout=300)
```

Paramiko's `timeout` parameter on `exec_command` is a **socket-level** receive timeout, not a wall-clock command duration limit. It governs how long individual `recv()` calls block, not the total time the command runs. If the remote k3s install stalls mid-execution while keeping the TCP connection alive (e.g., periodic keepalives, a hung package download), the 300-second timeout will never trigger, and the provisioner hangs indefinitely.

#### Remediation

Wrap the SSH operation in a thread with a real deadline:

```python
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

def _run_with_deadline(fn, deadline_seconds):
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(fn)
        try:
            return future.result(timeout=deadline_seconds)
        except FuturesTimeout:
            raise RuntimeError(f"Command exceeded {deadline_seconds}s wall-clock deadline")
```

Alternatively, set `stdout.channel.settimeout(300)` and read in a loop that checks elapsed wall time.

---

### 🔵 LOW-8 — `TOKEN_RE` Allows `:` — Weaker Injection Guard Than It Appears

**File:** `scripts/provision_cluster.py`, line 38
**CWE:** [CWE-185 — Incorrect Regular Expression](https://cwe.mitre.org/data/definitions/185.html)
**Status:** New

#### Description

```python
TOKEN_RE = re.compile(r"^[A-Za-z0-9:_\-]{10,512}$")
```

The `:` character is included in the allowlist to accommodate real k3s token formats like `K10<base64>::server:<base64>`. While `shlex.quote()` is the primary injection defense, the colon's presence in the regex means the regex alone provides weaker structural validation than it appears to. If `shlex.quote()` is ever removed or bypassed in a refactor, the regex will not catch tokens containing `::` sequences that could be exploited in certain shell contexts.

Additionally, there is no check that the token actually matches the known k3s structural format, so a string like `aaaaaaaaaa:::::::::::` (10+ chars, all valid characters) passes the regex but is clearly not a valid k3s token.

#### Remediation

Add a comment making the defense-in-depth relationship between `TOKEN_RE` and `shlex.quote()` explicit:

```python
# TOKEN_RE is a structural sanity check — shlex.quote() is the primary injection defense.
# ':' is required by the k3s token format: K10<base64>::server:<base64>
TOKEN_RE = re.compile(r"^[A-Za-z0-9:_\-]{10,512}$")
```

Consider strengthening to a structural match for the known k3s token format:

```python
# Matches: K10<base64+padding>::<role>:<base64+padding>
TOKEN_RE = re.compile(r"^K10[A-Za-z0-9+/=]+::[a-z]+:[A-Za-z0-9+/=]+$")
```

---

## Remediation Priority

| Priority | ID | Effort | Impact |
|---|---|---|---|
| 1 | HIGH-1: Residual shell-string injection | Medium | Eliminates remaining RCE surface on cluster nodes |
| 2 | MEDIUM-4: `None` labels AttributeError in PSA check | Low | Prevents false compliance pass on unlabeled namespaces |
| 3 | MEDIUM-3: `hostIPC` gap | Low | Closes container escape blind spot |
| 4 | MEDIUM-5: kubeconfig world-readable | Low | Prevents local privilege escalation via leaked credentials |
| 5 | MEDIUM-2: `_check_no_latest_tags` misses initContainers | Low | Closes last remaining `_all_containers()` gap |
| 6 | LOW-6: Path guard fragile at root | Low | Hardens output path validation edge case |
| 7 | LOW-8: TOKEN_RE comment + structural match | Low | Improves future-maintainer safety |
| 8 | LOW-7: Paramiko timeout wall-clock | Medium | Prevents indefinite hangs during provisioning |

---

## Dependency CVE Check

Run the following after installing to catch any known CVEs in the current dependency set:

```bash
pip install pip-audit
pip-audit -r requirements.txt
```

Notable changes from the original dependency set:

| Change | Impact |
|---|---|
| `paramiko>=3.4.0` added | Replaces `subprocess` SSH — positive security change. Monitor for CVEs. |
| Dev deps moved to `pyproject.toml [dev]` | Cleaner production install surface |
| `pytest`/`black`/`ruff`/`mypy` removed from `requirements.txt` | Reduced attack surface in production environments |

---

## Build Instructions (Current)

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install runtime dependencies only
pip install -r requirements.txt
pip install -e .

# Install with dev tools
pip install -e ".[dev]"

# Verify CLI is available
klustershield --version

# Lint
ruff check klustershield/
mypy klustershield/

# Check for dependency CVEs
pip install pip-audit
pip-audit -r requirements.txt
```

> **Note:** The `enforce` and `audit` subcommands will display a user-friendly error message until the `klustershield/enforcer/` and `klustershield/auditor/` packages are implemented.

---

*Report generated by Claude Code static analysis — 2026-02-21*
*Supersedes findings in `SECURITY_REPORT.md` for resolved items. Both reports should be retained for audit trail purposes.*
