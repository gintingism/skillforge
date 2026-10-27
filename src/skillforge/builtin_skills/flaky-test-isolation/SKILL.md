---
name: flaky-test-isolation
description: Diagnose and eliminate non-deterministic test failures caused by async race conditions, unseeded randoms, state leakage, or clock skew. Use when tests fail intermittently in CI or pass inconsistently.
license: MIT
compatibility: Python (pytest), Node.js (jest/vitest), Go
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Flaky Test Isolation & Cure Protocol

A test that passes 9 times out of 10 is a broken test. Agents must never "fix" a flaky test by adding retries or superficial sleeps. Follow this deterministic isolation procedure.

## 1. Force Deterministic Failure
Before applying any fix, prove the flakiness is reproducible:
1. Run the suspected test in a stress loop:
   ```bash
   # Python (pytest)
   pytest tests/test_suspect.py --count=50 -x
   # Node.js (jest)
   for i in {1..30}; do npm test -- test_suspect.test.ts || break; done
   ```
2. If it only fails in CI, simulate CI constraints:
   - Run under CPU throttling or constrained memory.
   - Shuffle test execution order (`pytest -p randomly` or `--random-order`).

## 2. Inspect the 4 Flakiness Culprits
- **Culprit A: State Leakage Across Tests**:
  - Cause: Module-level variables, unclosed DB connections, or singleton caches lingering from prior tests.
  - Test: Run the failing test in isolation (`pytest tests/test_suspect.py::test_case`). If it passes alone but fails in a suite, state is leaking.
  - Fix: Add explicit teardown/cleanup fixtures and reset singletons between runs.
- **Culprit B: Wall-Clock & Timezone Dependencies**:
  - Cause: Comparing `datetime.utcnow()` with fixed timestamps, or crossing midnight/leap-seconds.
  - Fix: Freeze time using `time-machine`, `freezegun`, or mock timers. Never assert `now() == expected`.
- **Culprit C: Arbitrary Sleep Calls**:
  - Cause: Using `time.sleep(1)` waiting for async workers or socket listeners.
  - Fix: Replace arbitrary delays with condition-based polling with an explicit timeout.
- **Culprit D: Unordered Set / Map Assertions**:
  - Cause: Database queries returning unordered rows or dictionaries compared against fixed lists.
  - Fix: Add deterministic `ORDER BY` clauses or assert set equality rather than list index equality.

## 3. Proof of Cure
A flaky test is only considered resolved when it executes 50 consecutive runs successfully in both forward and randomized test order.
