# Lockfile Integrity Audit Checklist

## Review Criteria for Dependency Updates

When reviewing git diffs on lockfiles (`package-lock.json`, `poetry.lock`, `uv.lock`, `skillforge.lock`), verify each check:

| Checkpoint | Target Indicator | Risk Level | Mitigation |
| :--- | :--- | :--- | :--- |
| **Integrity Hash Drift** | Same package version with altered SHA-512 / SHA-256 digest | Critical | Reject commit; verify upstream package registry for compromised release |
| **Unapproved Registry** | URL host pointing outside `registry.npmjs.org` or `pypi.org` | High | Revert to official index or verify enterprise registry mirror configuration |
| **Unpinned Top-Level Bump** | `^` or `~` semver range resolving to an unexpected major/minor release | Medium | Pin to exact version or re-run lockfile generation in clean environment |
| **Lifecycle Script Injection** | Addition of `scripts.postinstall` invoking shell commands | High | Inspect bundled script source before permitting installation |

## Remediation Workflow

1. **Rollback Suspicious Diffs**:
   If an unexpected integrity hash appears during dependency installation, restore the lockfile from git:
   ```bash
   git checkout HEAD -- package-lock.json poetry.lock skillforge.lock
   ```

2. **Clean Cache Re-verification**:
   Clear the local package cache to ensure corrupted artifacts are evicted before re-locking:
   ```bash
   npm cache clean --force
   pip cache purge
   ```
