---
name: supply-chain-lockfile-guard
description: Verify lockfile cryptographic integrity, detect unpinned runtime package installations, and audit post-install lifecycle scripts. Use when updating dependencies, modifying lockfiles, or reviewing supply-chain security.
license: MIT
allowed-tools: Read Grep Glob Bash
metadata:
  version: "1.0"
  category: "security"
---

# Supply Chain Lockfile Guard

Package managers use lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`, `skillforge.lock`) to guarantee reproducible, bit-for-bit identical dependency installations across developer workstations and CI/CD environments.

A compromised or desynchronized lockfile allows malicious actors to smuggle typosquatted packages, altered SHA-512 hashes, or dangerous post-install lifecycle hooks into production builds.

## Mandatory Lockfile Verification Rules

1. **Deterministic Lockfile Installations Only**
   - In automated scripts and CI pipelines, always invoke freeze-mode install commands (`npm ci`, `poetry install --frozen`, `uv sync --frozen`, or `skillforge sync`).
   - Never run unpinned commands like `npm install <pkg>` or `pip install <pkg>` without an exact pinned version constraint in production instructions.

2. **Inspect Hash Mismatches and Registry URLs**
   - Ensure all package download URLs point to official public registries (`registry.npmjs.org`, `pypi.org`) or pre-approved internal enterprise mirrors.
   - Reject lockfile diffs where an existing package version changes its resolved hash digest without an explicit version increment.
   - Consult `references/lockfile-audit-checklist.md` for the line-by-line review checklist.

3. **Audit Post-Install Lifecycle Scripts**
   - Watch for `preinstall`, `install`, or `postinstall` entries in JavaScript dependencies.
   - Restrict scripts from invoking network clients (`curl`, `wget`) or spawning unauthorized shells during package extraction.

4. **Verify SkillForge Integrity**
   - Run `skillforge verify` to compare active skills against `skillforge.lock` without making network requests:

```bash
skillforge verify --project .
```
