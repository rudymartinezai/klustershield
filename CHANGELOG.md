# Changelog

All notable changes to KlusterShield will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Planned
- SBOM generation using CycloneDX
- Automated remediation suggestions with `klustershield fix`
- GitHub Actions integration example
- Web dashboard (FastAPI + HTMX)
- CMMC Level 2 control overlay
- EKS and AKS compatibility testing

---

## [0.1.0] — 2025-02-19

### Added
- **Provisioner** — Hardened namespace creation with RBAC, NetworkPolicies,
  ResourceQuota, LimitRange, and PodSecurityAdmission labels
- **Scanner** — 12-check NIST SP 800-218 compliance engine with weighted scoring
- **HTML Report** — Dark-mode compliance report with per-control PASS/FAIL/WARN status
- **JSON Report** — Machine-readable output for CI/CD pipeline integration
- **OPA Gatekeeper** — Constraint template blocking privileged containers at admission
- **Network Policies** — Zero-trust default-deny manifests with DNS exception
- **Proxmox Provisioner** — Automated k3s cluster bootstrapping via Proxmox API
- **CLI** — Full `klustershield` command with provision, scan, enforce, audit subcommands
- **Documentation** — NIST control mapping, Proxmox setup guide, architecture overview
- Apache 2.0 license (chosen for explicit patent grant — safe for defense/gov environments)

### NIST SP 800-218 Coverage (v0.1.0)
- PO.1.1 ✅  PO.3.2 ✅
- PS.1.1 ✅  PS.2.1 ✅
- PW.4.1 ✅  PW.7.2 ✅
- RV.1.3 ✅  RV.3.3 ✅
- DS.1.1 ✅  DS.2.1 ✅
- PV.1.1 ✅  PV.1.2 ✅
