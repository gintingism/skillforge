---
name: antislop-code
description: Enforce rigorous code comment hygiene, anti-overengineering constraints, and eliminate AI-generated narrative filler while preserving valuable domain invariants. Use when reviewing code, refactoring modules, or auditing pull requests.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Anti-Slop Code Hygiene

Eliminate low-value AI-generated boilerplate, generic narrative comments, and speculative over-engineering. Code should be idiomatic, self-documenting, and focused strictly on the current problem.

## Comment Hygiene Rules

### What to Ban (Delete on Sight):
- **Trivial Echo Comments**:
  ```python
  # BAD:
  # Initialize the count to zero
  count = 0
  # Loop over items in list
  for item in items:
  ```
- **Process Narratives**: Comments describing what the developer or agent just did ("Added this function to fix bug 123", "Now we check if user is valid").
- **Section Dividers for Trivial Code**: Comments like `// ================== HELPER FUNCTIONS ==================`.

### What to Keep & Require:
- **Non-Obvious Invariants**: Explanations of *why* an unusual algorithmic choice or workaround was made.
- **External Protocol / Hardware Quirks**: References to specific third-party API bugs, RFC sections, or operating system quirks.
- **Mathematical Formulations**: Formulas and units of measurement.

## Architectural Discipline
1. **No Speculative Generality (YAGNI)**: Do not create plugin systems, dynamic registries, or generic factory layers for problems that currently only have one implementation.
2. **Contract Preservation**: Preserve existing docstrings, public API signatures, and type annotations unless breaking changes are explicitly requested.
3. **No Gratuitous Dependencies**: Prefer standard library capabilities before importing heavyweight external packages.
