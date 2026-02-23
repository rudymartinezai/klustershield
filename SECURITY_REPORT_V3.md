# KlusterShield Security Vulnerability Report — Re-scan V3

**Project:** KlusterShield v0.1.0
**Language:** Python 3.11+
**Scan Date:** 2026-02-21
**Auditor:** Claude Code Static Analysis
**Previous Reports:** `SECURITY_REPORT.md` (round 1), `SECURITY_REPORT_V2.md` (round 2)
**Scope:** Full source — `klustershield/`, `scripts/`, `manifests/`, `requirements.txt`, `pyproject.toml`

---

## Re-scan Summary

This report reflects a full re-scan after changes applied since `SECURITY_REPORT_V2.md`. All 8 prior findings have been addressed. 3 low-severity items remain.

### Resolved Since Last Scan (V2 → V3)

| V2 ID | Finding | Status |
|---|---|---|
| HIGH-1 | Residual shell-string injection surface in `exec_command` | ✅ Fixed |
| MEDIUM-2 | `_check_no_latest_tags` missed `initContainers` | ✅ Fixed |
| MEDIUM-3 | `hostIPC` not checked in host namespace scan | ✅ Fixed |
| MEDIUM-4 | `ns.metadata.labels` could be `None` → `AttributeError` | ✅ Fixed |
| MEDIUM-5 | kubeconfig written without `0o600` permissions | ✅ Fixed |
| LOW-6 | Path traversal guard fragile when CWD is `/` | ✅ Fixed |
| LOW-7 | Paramiko `exec_command` timeout was socket-level only | ✅ Fixed |
| LOW-8 | `TOKEN_RE` allowed `:` with no structural comment | ✅ Fixed |

**Changes confirmed:**

- `provision_cluster.py` — `_build_env_exec()` helper separates env vars from command arguments and applies `shlex.quote()` throughout; k3s installer is downloaded to `/tmp/k3s-install.sh` then executed as a separate step, breaking the `curl | sh` pipeline injection surface. `ThreadPoolExecutor` + `future.result(timeout=300)` enforces wall-clock deadline. `write_kubeconfig_secure()` uses `os.open()` with `O_CREAT | O_WRONLY | 0o600` + `os.chmod()`. `TOKEN_RE` updated to structural k3s format with `LEGACY_TOKEN_RE` fallback and explanatory comment.
- `engine.py` — `_check_no_latest_tags` now uses `_all_containers()`. `_check_host_namespaces` now checks `host_ipc`. `_resolve_output_path` guards against root CWD with `safe_base == Path(safe_base.anchor)` and uses `startswith(str(safe_base) + os.sep)`. `(ns.metadata.labels or {}).get(...)` guards the PSA check.

---

## Current Severity Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| 🟡 MEDIUM | 0 |
| 🔵 LOW | 3 |
| **Total** | **3** |

---

## Active Findings

---

### 🔵 LOW-1 — `LEGACY_TOKEN_RE` Allows `.` (Period) — Broader Than Necessary

**File:** `scripts/provision_cluster.py`, line 42
**CWE:** [CWE-185 — Incorrect Regular Expression](https://cwe.mitre.org/data/definitions/185.html)
**NIST 800-218:** PS.1.1

#### Description

The legacy fallback token validator includes `.` (period) in its character class:

```python
LEGACY_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:\-]{10,512}$")
```

The period has no known role in any k3s token format (current or historical). Its inclusion unnecessarily widens the allowlist. While `shlex.quote()` remains the primary injection defense, minimising the allowlist to only characters with a documented purpose in the token format reduces the attack surface in case `shlex.quote()` is removed or bypassed in a future refactor.

Additionally, `LEGACY_TOKEN_RE` has no upper bound tighter than 512 characters and no lower bound tighter than 10, meaning an extremely short or long legacy token would pass. The primary `TOKEN_RE` is more structurally specific.

#### Remediation

Remove `.` from `LEGACY_TOKEN_RE` and add a comment documenting what historical token format necessitates the fallback:

```python
# LEGACY_TOKEN_RE covers older k3s token formats that predate the K10:: structure.
# Excludes '.' as it has no known role in any k3s token format.
LEGACY_TOKEN_RE = re.compile(r"^[A-Za-z0-9:_\-]{10,512}$")
```

If the legacy format is no longer needed (k3s >= 1.20 uses the K10 format), consider removing `LEGACY_TOKEN_RE` entirely and enforcing `TOKEN_RE` exclusively.

---

### 🔵 LOW-2 — `_run_remote_checked` Is a No-Op Wrapper — Dead Abstraction

**File:** `scripts/provision_cluster.py`, lines 175–177
**CWE:** [CWE-561 — Dead Code](https://cwe.mitre.org/data/definitions/561.html)

#### Description

```python
def _run_remote_checked(ip: str, ssh_user: str, ssh_key: str, known_hosts: str, command: str) -> str:
    """Wrapper that keeps command dispatch in one place for additional policy checks."""
    return run_remote(ip, ssh_user, ssh_key, known_hosts, command)
```

This function is a pure pass-through with no additional logic. Its docstring promises "additional policy checks" that do not exist. All callers (`_download_k3s_installer`, `install_k3s_control_plane`, `install_k3s_worker`, `fetch_kubeconfig`) call it instead of `run_remote` directly.

This is a low-severity issue but creates two risks:
1. A future developer may add sensitive logic to `_run_remote_checked` assuming all SSH calls go through it, not realising `run_remote` can still be called directly.
2. The misleading docstring ("additional policy checks") implies a security contract that is not enforced.

#### Remediation

Either:
1. **Implement the promised policy checks** (e.g., command allowlisting, audit logging of remote commands, rate limiting) to justify the wrapper's existence.
2. **Remove the wrapper** and call `run_remote` directly, or rename it to something that doesn't imply security policy enforcement if it's only intended as a single dispatch point.

---

### 🔵 LOW-3 — `_download_k3s_installer` Fetches Over HTTPS With No Checksum Verification

**File:** `scripts/provision_cluster.py`, lines 186–191
**CWE:** [CWE-494 — Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
**NIST 800-218:** RV.1.3, PO.3.2

#### Description

The k3s installer is downloaded directly from `https://get.k3s.io` and immediately executed without verifying its integrity:

```python
def _download_k3s_installer(ip: str, ssh_user: str, ssh_key: str, known_hosts: str) -> None:
    download_cmd = (
        f"curl -sfL https://get.k3s.io -o {shlex.quote(K3S_INSTALLER_PATH)} "
        f"&& chmod +x {shlex.quote(K3S_INSTALLER_PATH)}"
    )
    _run_remote_checked(ip, ssh_user, ssh_key, known_hosts, download_cmd)
```

Improvements over the original: the install script is now downloaded first and executed separately (no longer `curl | sh`), which is a meaningful hardening step. However, there is still no SHA-256 checksum verification against the official k3s release manifest before execution. If `get.k3s.io` is compromised, delivers tampered content due to a CDN attack, or if DNS is poisoned on the remote node's network, a malicious installer would be executed silently.

k3s publishes SHA-256 checksums at `https://github.com/k3s-io/k3s/releases/download/<version>/sha256sum-amd64.txt` for this purpose.

#### Remediation

After downloading, verify the checksum before executing:

```python
# Download the specific versioned binary directly (not the install script wrapper)
# and verify its SHA-256 against the published release checksum.
checksum_url = f"https://github.com/k3s-io/k3s/releases/download/{safe_version}/sha256sum-amd64.txt"
verify_cmd = (
    f"curl -sfL {shlex.quote(checksum_url)} -o /tmp/k3s-sha256.txt && "
    f"curl -sfL https://get.k3s.io -o {shlex.quote(K3S_INSTALLER_PATH)} && "
    f"grep 'install.sh' /tmp/k3s-sha256.txt | sha256sum --check --status && "
    f"chmod +x {shlex.quote(K3S_INSTALLER_PATH)}"
)
```

Alternatively, pin to a pre-verified installer image in an internal registry for air-gapped deployments (already a stated use case in the README).

---

## Cumulative Fix History

| Round | Findings | Critical | High | Medium | Low |
|---|---|---|---|---|---|
| Initial scan (`SECURITY_REPORT.md`) | 15 | 2 | 5 | 4 | 4 |
| After V1 fixes (`SECURITY_REPORT_V2.md`) | 8 | 0 | 1 | 4 | 3 |
| After V2 fixes (this report) | **3** | **0** | **0** | **0** | **3** |

---

## Overall Security Posture Assessment

The codebase has progressed from a critically vulnerable state (2 critical, 5 high findings) to a clean low-severity-only profile across three rounds of remediation. The three remaining findings are all informational/defence-in-depth concerns rather than exploitable vulnerabilities:

- **LOW-1** is a minor regex hygiene issue with no direct exploitability given `shlex.quote()` is the primary defence.
- **LOW-2** is a code quality / future-maintainer risk rather than a current vulnerability.
- **LOW-3** is a supply chain integrity gap that represents a real (if low-probability) risk for production deployments, particularly relevant given the project's stated government/defence audience.

For a NIST 800-218 compliance context, **LOW-3 is the most meaningful remaining item** to address before production use, as it touches RV.1.3 (pinned/verified software components) and PO.3.2 (toolchain integrity).

---

## Dependency CVE Check

No dependency changes since V2. Run to confirm current state:

```bash
pip install pip-audit
pip-audit -r requirements.txt
```

---

## Build Instructions (Current)

```bash
python -m venv .venv
source .venv/bin/activate

# Runtime only
pip install -r requirements.txt
pip install -e .

# With dev tools
pip install -e ".[dev]"

klustershield --version
ruff check klustershield/
mypy klustershield/
pip-audit -r requirements.txt
```

---

*Report generated by Claude Code static analysis — 2026-02-21*
*This is the third and final report in the audit series. For full history see `SECURITY_REPORT.md` → `SECURITY_REPORT_V2.md` → `SECURITY_REPORT_V3.md`.*
