---
name: skill-architect
description: Design, author, and refactor SKILL.md packages, AGENTS.md catalogs, and CLAUDE.md instructions using progressive disclosure and context-budget discipline. Use when creating or optimizing agent skills and instruction files.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Skill Architect Protocol

Author high-signal, low-token agent documents (`SKILL.md`, `AGENTS.md`, `CLAUDE.md`) that maximize execution accuracy without bloating the startup context window.

## 1. Three-Tier Context Hierarchy

1. **Tier 1 — Always-Loaded Pointer (`name` + `description`)**:
   - Every model-invoked skill's `name` and `description` remain in the startup context on every turn.
   - Front-load the capability and explicit trigger condition within the first 200 characters: *"Design, author, and refactor... Use when..."*.
   - For user-only slash workflows that should never auto-trigger, set `disable-model-invocation: true` to drop startup token cost to zero.
2. **Tier 2 — On-Demand Procedure (`SKILL.md` body)**:
   - Keep `SKILL.md` under **500 lines** and **5,000 tokens**.
   - Include only the decision tree, numbered workflow steps, and verification commands needed during execution.
3. **Tier 3 — Disclosed Deep Reference (`references/` & `scripts/`)**:
   - Move large schemas, edge-case tables, and deterministic helpers into `references/` or `scripts/`.
   - Link each file with an explicit load condition (for example: read `references/mechanics.md` when choosing frontmatter fields or invocation modes).

## 2. Authoring Rules

- **Prefer Pointers over Copies**: Point to canonical files (`src/auth/middleware.py`) instead of pasting code blocks that go stale.
- **Lead Every Step with the Action**: Start bullet points and numbered steps with the verb or command (`Run pytest -q`, `Inspect lockfile`, `Reject unsigned payloads`).
- **Steer Positively**: Whenever prohibiting an anti-pattern, state the concrete alternative in the same sentence (*"Do not mock the database; run against the local SQLite fixture"*).
- **Define Checkable Exit Gates**: Replace vague directives (*"ensure high quality"*) with executable gates (`skillforge audit <path> --strict`, `pytest`, `mypy`).

## 3. Progressive Disclosure Reference

- Read `references/mechanics.md` when configuring frontmatter fields, `disable-model-invocation`, or context budget thresholds.
