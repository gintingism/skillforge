---
name: human-in-the-loop
description: Enforce explicit human approval boundaries before executing irreversible actions, deploying code, modifying schemas, or making external financial/data mutations. Use when building safe autonomous agent workflows.
license: MIT
compatibility: Universal
metadata:
  version: "1.1.0"
  author: "SkillForge Team"
---

# Human-in-the-Loop Protocol (HITL)

Maintain strict authorization boundaries to ensure autonomous agents never perform irreversible actions or sensitive transactions without explicit, out-of-band human consent.

## Verification Tiers

1. **Auto-Executable (Tier 0)**:
   - Read-only operations: file reads, searching codebases, static analysis, running sandboxed unit tests.
2. **Review Recommended (Tier 1)**:
   - Non-destructive workspace changes: modifying internal application files, writing tests, creating branches.
3. **Mandatory Human Approval (Tier 2)**:
   - Destructive operations: git push to remote, database drops/migrations, deleting files outside scratch, executing shell commands requiring network or elevated credentials.
   - Formulate approval prompts specifying:
     - Exact command or file diff.
     - Potential blast radius.
     - Rollback procedure.
