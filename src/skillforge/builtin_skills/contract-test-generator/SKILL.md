---
name: contract-test-generator
description: Author property-based fuzz tests and contract invariants to verify edge cases, serialization symmetry, and boundary conditions. Use when testing schemas, parser logic, or public library APIs.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Contract Test Generator Protocol

Traditional example-based tests ($N = 2$ fixtures) miss edge cases, numeric boundary overflows, and Unicode malformations. Author property-based contract tests that assert mathematical invariants over generated random input spaces.

## 1. Property-Based Test Principles

Define invariants that must hold true for *all* valid inputs, not just cherry-picked samples:

1. **Roundtrip Symmetry (Serialization Invariant)**:
   `deserialize(serialize(x)) == x`
   Assert that parsing and rendering preserve identity across Unicode strings, nested mappings, and timestamps.
2. **Idempotence Invariant**:
   `f(f(x)) == f(x)`
   Assert that running a formatting, migration, or normalization pass a second time produces identical output.
3. **Monotonicity & Invariant Bounds**:
   Output lengths, sorted orders, or checksums must satisfy predictable algebraic properties ($len(dedup(x)) \le len(x)$).

## 2. Test Harness Frameworks

- **Python**: Use `hypothesis`
  ```python
  from hypothesis import given, strategies as st

  @given(st.text(min_size=1, max_size=200))
  def test_roundtrip_parsing(sample: str) -> None:
      assert parse(render(sample)) == sample
  ```
- **TypeScript / Node.js**: Use `fast-check`
  ```typescript
  import fc from "fast-check";

  test("roundtrip JSON schema", () => {
    fc.assert(fc.property(fc.record({ id: fc.uuid(), val: fc.string() }), data => {
      expect(decode(encode(data))).toEqual(data);
    }));
  });
  ```

## 3. Verification Gate

- Run the test suite with a randomized seed and at least 100 test iterations (`--hypothesis-seed` or default generator iterations).
- Ensure zero flakiness and deterministic error shrinking.
