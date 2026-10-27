---
name: systematic-debugging
description: Execute a disciplined four-phase root-cause investigation loop (Reproduce, Isolate, Hypothesize, Surgical Patch) before modifying code. Use when diagnosing failing tests, runtime crashes, race conditions, or performance regressions.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Systematic Debugging Protocol

Never modify code on guesswork. Follow the strict four-phase investigation loop to identify root causes and deliver surgical, verified fixes.

## Phase 1: Minimal Reproduction
1. Before editing any application file, construct a minimal, deterministic reproduction script or failing automated test case.
2. Confirm the reproduction fails with the exact reported error or symptom.
3. If reproduction fails, inspect environmental differences (OS, Python/Node version, network, permissions) before proceeding.

## Phase 2: Evidence Collection & Isolation
1. Inspect the stack trace: identify the exact failure point (innermost frame) and trigger boundary (outermost frame).
2. Gather runtime evidence via non-invasive logging or debugger inspection:
   - Variable values at state transitions.
   - Input payloads and invariants.
3. Use binary search (git bisect or comment isolation) for regressions in large codebases.

## Phase 3: Falsifiable Hypotheses
1. Formulate 1 to 3 explicit hypotheses explaining why the failure occurs:
   - "Component A passes null to Component B because condition X does not handle edge case Y."
2. For each hypothesis, identify a testable prediction that would disprove it.
3. Rank hypotheses by probability and test the simplest first.

## Phase 4: Surgical Patch & Verification
1. Apply the narrowest responsible fix at the root layer—never mask symptoms with superficial null-checks or swallow exceptions.
2. Run the reproduction test: verify it now passes.
3. Run the full test suite: verify zero unintended regressions.
4. Clean up any temporary debug logs before submitting changes.
