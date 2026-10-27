---
name: self-improving-agent
description: Extract concrete lessons and operational heuristics from runtime failures, user corrections, and test cycles into durable project memory. Use when capturing recurring debugging patterns or user preferences.
license: MIT
compatibility: Universal
metadata:
  version: "1.1.0"
  author: "SkillForge Team"
---

# Self-Improving Agent Protocol

Translate execution failures and user corrections into durable project rules and skills, preventing repeating the same mistakes across sessions.

## Learning Cycle

1. **Trigger on Correction**:
   - When a user corrects an assumption or a command repeatedly fails, record the failure mode immediately.
2. **Formulate Invariant**:
   - What failed? (Root cause, not symptom).
   - What is the invariant rule? (e.g., "Always run pnpm with BypassSandbox: true on Windows").
   - Where should it be codified? (`.cursor/rules`, `.claude/skills`, `AGENTS.md`, or test assertions).
3. **Verification**:
   - Write a regression test or validation script verifying that the failure cannot recur silently.
