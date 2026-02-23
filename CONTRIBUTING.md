# Contributing to KlusterShield

Thanks for your interest in contributing. KlusterShield is a security-focused compliance tool — contributions are welcome but held to a high standard, especially around correctness of NIST/CMMC control mappings.

---

## How to contribute

### 1. Fork and clone

```bash
git clone https://github.com/<your-username>/klustershield.git
cd klustershield
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-cov ruff black mypy bandit pip-audit
```

### 2. Create a branch

```bash
git checkout -b fix/your-fix-name
# or
git checkout -b feat/your-feature-name
```

### 3. Make your changes

- Keep PRs focused — one fix or feature per PR
- If you're adding a compliance check, include the NIST/CMMC control ID and a link to the source document
- All new code must have tests

### 4. Run checks locally before pushing

```bash
# Lint
ruff check klustershield/ scripts/
black --check klustershield/ scripts/

# Tests
PYTHONPATH=. pytest tests/ --cov=klustershield --cov-report=term-missing

# Security
bandit -r klustershield/ scripts/ --severity-level medium
pip-audit -r requirements.txt
```

### 5. Open a Pull Request

- Reference the issue your PR closes (`Closes #123`)
- Fill out the PR template completely
- CI must pass — the pipeline runs lint, type check, tests, SAST, and dependency scanning automatically

---

## What we're looking for

| Type | Welcome |
|------|---------|
| Bug fixes | ✅ Always |
| New NIST control checks | ✅ With source citation |
| CMMC L1/L2 control mapping | ✅ See roadmap issues |
| FedRAMP controls | ✅ See roadmap issues |
| Test coverage improvements | ✅ Always |
| Docs and examples | ✅ Always |
| New CLI commands | ⚠️ Open an issue first to discuss |
| Architecture changes | ⚠️ Open an issue first |

---

## Compliance control contributions

If you're adding or modifying a compliance check:

1. **Cite the source** — link to the specific NIST SP, CMMC practice, or FedRAMP control in a code comment
2. **Don't guess** — if you're unsure whether a Kubernetes configuration satisfies a control, flag it as `WARN` not `PASS`
3. **Test edge cases** — test PASS, FAIL, WARN, and SKIP conditions for every check
4. **Update the control mapping** — if it maps to multiple frameworks, update the mapping YAML

---

## Reporting security vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Email `rudy@rudymartinez.ai` with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

We'll respond within 48 hours and coordinate a fix before public disclosure.

---

## Code of Conduct

Be professional. This project targets defense and government environments — keep discussions technical and respectful.

---

## License

By contributing, you agree your contributions are licensed under the Apache License 2.0 with the explicit patent grant that license provides.
