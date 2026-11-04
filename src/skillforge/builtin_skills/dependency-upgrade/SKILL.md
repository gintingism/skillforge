---
name: dependency-upgrade
description: Manage methodical dependency updates with changelog and advisory review, incremental version bumps, automated regression test runs, and rollback plans. Use when updating packages, resolving security vulnerabilities, or modernizing outdated toolchains.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Methodical Dependency Upgrade Protocol

Upgrades should never be mass bulk operations that conceal breaking changes. Execute incremental, tested bumps with clear rollback paths.

## Phase 1: Vulnerability and Outdated Audit
1. Identify outdated packages using ecosystem tooling:
   - Python: `pip list --outdated` or `uv pip list --outdated`
   - Node: `npm outdated` or `pnpm outdated`
   - Rust: `cargo outdated`
2. Cross-reference dependencies against security advisories (`npm audit`, `pip-audit`, `cargo audit`).
3. Classify updates by semver risk: Patch (low), Minor (medium), Major (high).

## Phase 2: Changelog and Breaking Change Review
1. For any Minor or Major bump, review release notes and migration guides.
2. Search for deprecated APIs or renamed configuration options.
3. Verify minimum runtime engine compatibility (Node version, Python version).

## Phase 3: Incremental Upgrade Execution
1. Update one dependency (or tightly coupled pair) at a time.
2. Update the lockfile (`package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`, `Cargo.lock`) alongside the manifest.
3. Avoid wildcard or unpinned upgrades in production projects.

## Phase 4: Regression Testing and Verification
1. Run local test suites immediately following the single bump.
2. Run build scripts, bundling, and static type checks.
3. Test runtime entry points or smoke tests if external I/O behavior is affected.

## Phase 5: Rollback and Commit Invariants
1. If an upgraded dependency breaks tests and requires extensive unplanned refactoring, revert the bump immediately.
2. Commit each successful upgrade independently with context:
   - Example: `chore(deps): upgrade fastapi from 0.110.0 to 0.115.0`
