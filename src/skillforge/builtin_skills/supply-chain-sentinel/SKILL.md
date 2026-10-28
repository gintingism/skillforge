---
name: supply-chain-sentinel
description: Verify third-party package existence, registry metadata, age, and CVE status before installing dependencies. Use when adding packages, upgrading libraries, or editing requirements and lockfiles.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Supply Chain Sentinel Protocol

Prevent dependency hallucination, typosquatting attacks, and CVE introduction when installing third-party libraries across Python, Node.js, and modern package ecosystems.

## 1. Registry Existence & Legitimacy Verification

Never guess a package name or install an unverified import. Always verify the package exists on the upstream index before invoking install commands:

- **Python (PyPI)**:
  `python -m pip index versions <package_name>`
- **Node.js (npm / pnpm)**:
  `npm view <package_name> name time.created dist-tags`

### Red Flags:
1. **Package Age < 30 Days**: Newly published packages claiming common utility names are prime typosquatting vectors.
2. **Zero or Minimal Downloads**: Avoid packages with near-zero download volume when alternative vetted standard libraries exist.
3. **Typosquatting Distance**: Watch for single-character swaps (`reqeusts` vs `requests`, `colorama-v2` vs `colorama`).

## 2. Automated Vulnerability Auditing

Immediately after package addition or dependency upgrades, run an explicit vulnerability scanner:

- **Python**:
  `pip-audit` or `safety check`
- **Node.js**:
  `pnpm audit` or `npm audit --audit-level=high`

## 3. Lockfile Pinning & Integrity Gate

1. Pin exact or compatible version constraints in `pyproject.toml`, `package.json`, or requirements files.
2. Commit the generated cryptographic lockfile (`pnpm-lock.yaml`, `package-lock.json`, `poetry.lock`, or `uv.lock`) alongside the dependency definition.
3. Verify test suites pass without unpinned transitive regressions.
