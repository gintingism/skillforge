---
name: blast-radius-containment
description: Analyze upstream callers, downstream dependencies, and enforce strict minimal-diff boundaries before modifying shared code. Use when modifying core utilities, database models, public API signatures, or widely imported types.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Blast Radius Containment Protocol

Autonomous agents frequently cause regressions by expanding the scope of a fix beyond the original failure boundary. Follow this protocol to measure and constrain the blast radius before touching shared code.

## 1. Upstream Call-Graph Audit
Before editing any function, class, or method imported by more than one file:
1. **Find All Call Sites**: Run a full reference search (via grep, ripgrep, or LSP `find-references`).
2. **Catalog Invariants**: Note what assumptions call sites make about:
   - Return types and nullability.
   - Exception types raised.
   - Positional vs keyword arguments.
3. If an edit requires changing call sites in more than 2 unrelated consumer modules, **stop**: create a backward-compatible adapter or deprecation shim instead of breaking the call sites in-place.

## 2. The File Touch Budget
Enforce the Rule of Least Mutation:
- **Target Budget**: A bug fix should ideally touch 1 file and at most 1 companion test file.
- **Budget Exceeded Warning**: If an edit requires modifying >3 non-test files, pause and document why the existing architecture forces widespread coupling.
- **No Drive-by Refactoring**: Never reformat, reorder, or rename unrelated code in the same patch as a bug fix or feature addition.

## 3. Preservation Verification
Before committing or marking work complete:
1. Run `git diff --stat`: Verify that every modified file and line is strictly necessary for the stated goal.
2. Run the entire test suite (not just the local module test) to verify zero downstream breakage.
