---
name: code-review
description: Conduct disciplined multi-pass adversarial code reviews assessing correctness, security, performance, and test coverage. Use when reviewing diffs, pull requests, or staged changes before merging.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Adversarial Code Review Protocol

Deliver structured, high-signal reviews focused on substantive engineering risks. Never offer superficial styling critiques if automated linters can format the code.

## Phase 1: Context and Environment Discovery
1. Identify the project stack, language version, and package manager.
2. Locate existing linting and formatting configs (e.g. ESLint, Ruff, Prettier, Clippy).
3. Check test runner commands and active CI pipeline configurations.

## Phase 2: Multi-Pass Code Audit
Inspect changes systematically across four distinct dimensions:

### Pass 1: Correctness and Boundary Invariants
- Verify state mutations and null/undefined handling.
- Check off-by-one errors in loops, slices, and pagination offsets.
- Validate error propagation: ensure exceptions are neither swallowed nor left unhandled.
- Confirm schema migrations preserve backwards compatibility.

### Pass 2: Security and Data Flow
- Trace untrusted inputs from entrypoints to sinks (SQL queries, shell calls, HTML rendering).
- Verify authorization checks guard all sensitive resource endpoints.
- Check for hardcoded secrets, tokens, or credential leaks.
- Ensure rate limiting and payload validation boundaries are enforced.

### Pass 3: Performance and Concurrency
- Identify algorithmic bottlenecks (e.g. nested O(n^2) operations, unindexed DB queries).
- Detect N+1 query patterns in ORM relationships.
- Inspect concurrent operations for race conditions, deadlock risks, or unbounded memory allocations.

### Pass 4: Test Integrity and Regression Safety
- Confirm new code branches have corresponding automated tests.
- Evaluate test quality: check for assertions on exact outputs rather than weak truthiness.
- Ensure test mocks accurately reflect real service contracts.

## Phase 3: Actionable Review Output
Structure findings clearly:
1. Severity tag: Critical, Warning, or Suggestion.
2. Exact file path and line numbers.
3. Root problem explanation.
4. Concrete replacement diff illustrating the recommended fix.
