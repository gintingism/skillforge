---
name: git-workflow
description: Standardize Git hygiene with atomic conventional commits, pre-staging diff inspections, protected branch guardrails, and conflict pause protocols. Use when staging changes, writing commits, or resolving branch divergences.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Git Hygiene and Workflow Protocol

Enforce clean version control practices. Keep history bisectable, commits atomic, and protected branches safe from destructive operations.

## Phase 1: Pre-Staging Inspection
1. Run `git status` to identify all modified, added, or untracked files.
2. Review exact changes with `git diff` before staging.
3. Verify that sensitive artifacts (.env, credentials, temporary dumps, logs) are untracked and excluded in `.gitignore`.
4. Run linters and tests locally before creating commits.

## Phase 2: Atomic Staging and Commit Discipline
1. Stage related files together: one commit represents one logical change.
2. Separate refactoring or formatting changes from functional behavior additions.
3. Write commit messages following the Conventional Commits specification:
   - Format: `<type>(<scope>): <short description in imperative mood>`
   - Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`.
   - Example: `feat(security): add markdown installer scanner rule`
4. Avoid empty, vague, or combined messages like "update files" or "wip".

## Phase 3: Branch Safety and Divergence Management
1. Never force-push (`git push --force` or `-f`) to main or production branches.
2. When pulling upstream updates, prefer rebasing feature branches over merge commits to maintain linear history.
3. If merge conflicts occur:
   - Pause execution immediately.
   - Inspect conflicting blocks in both HEAD and incoming versions.
   - Resolve conflicts with verified intent and run full tests before committing.
   - Never use blind checkout strategies like `git checkout --ours` or `git checkout --theirs` without inspecting diffs.
