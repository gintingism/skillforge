---
name: test-driven-development
description: Enforce rigorous Red-Green-Refactor development cycles with automated test runner discovery, failing reproduction assertions, and raw terminal exit criteria. Use when implementing new features, writing bug reproductions, or refactoring existing modules.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Test-Driven Development (TDD) Protocol

Build reliable software by proving defects before patching and proving behavior before implementing. Follow the strict Red-Green-Refactor cycle.

## Phase 1: Environment and Runner Discovery
1. Inspect repository manifests to determine the project test framework:
   - Python: `pytest`, `unittest`
   - Node/TypeScript: `vitest`, `jest`, `playwright`
   - Rust: `cargo test`
   - Go: `go test ./...`
2. Run the test suite once to verify a clean baseline before writing code.

## Phase 2: Red (Failing Test First)
1. Write a minimal, expressive test case capturing the target requirement or defect.
2. Execute the specific test command in the terminal.
3. Confirm the test fails with the expected assertion error.
4. If the test fails due to a missing import or syntax error, correct the test harness until the failure strictly reflects the absent production feature.

## Phase 3: Green (Minimal Implementation)
1. Write the minimal production code necessary to make the failing test pass.
2. Avoid speculative generality, extra abstraction layers, or unrelated features.
3. Run the test command and verify it passes.

## Phase 4: Refactor (Clean Code Invariant)
1. Clean up the implementation: eliminate duplication, improve variable naming, and extract helpers where justified.
2. Run the full test suite to guarantee zero regressions.
3. Verify type checking and linting pass cleanly.

## Phase 5: Verification Exit Criteria
Do not declare completion without raw terminal output demonstrating:
- The newly added test passing.
- The existing test suite passing without regressions.
