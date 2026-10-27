---
name: context-compactor
description: Distill extensive agent session transcripts into dense knowledge states, active hypothesis ledgers, and verified file citation indices. Use when context windows approach limits or during multi-agent handoffs.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Context Compactor Protocol

Condense long-running agent execution history into a high-density structured state. Prevent context window overflow while preserving key artifacts, decisions, and paths.

## Compaction Ledger Format

When compacting context, emit the following structured sections:

1. **Active Goal**: 1-2 sentence statement of current objective.
2. **Current State & Progress**:
   - Completed milestones (checked items).
   - In-progress task.
   - Pending blockers.
3. **Decisions & Invariants Made**:
   - Key architectural choices and rationale.
   - Discarded approaches and reasons why.
4. **File & Symbol Citations**:
   - List only files actively modified or referenced: `path/to/file.py#L40-L80` with brief role.
5. **Pending Command Queue**:
   - Next immediate 1 to 3 actions to execute upon context resume.
