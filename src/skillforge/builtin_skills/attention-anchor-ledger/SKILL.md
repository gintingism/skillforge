---
name: attention-anchor-ledger
description: Anchor active state invariants and decision ledgers to prevent model attention degradation in long-context threads (100k+ tokens). Use when managing multi-turn agent sessions, tracking complex refactors, or debugging context drift.
license: MIT
allowed-tools: Read Grep Glob Bash
metadata:
  version: "1.0"
  category: "context"
---

# Attention Anchor Ledger

In autonomous coding sessions exceeding 100,000 tokens, LLMs suffer from the *lost-in-the-middle* phenomenon: instructions and architectural constraints established early in the dialogue fade from active attention as tool outputs and stack traces accumulate.

The **Attention Anchor Ledger** provides a compact, deterministic state record maintained at the top of long-running workflows to prevent context drift and hallucinated invariants.

## State Anchoring Protocol

1. **Maintain a 20-Line State Anchor**
   - At the beginning of complex multi-turn tasks, author or update a structured ledger documenting the verified baseline, active hypotheses, and immutable project invariants.
   - Consult `references/state-anchor-schema.md` for the exact markdown template and field definitions.

2. **Ground Truth over Recalled Memory**
   - When deciding next steps after multiple tool executions, re-read the anchor ledger rather than relying on model recall across earlier turns.
   - Any assumption not recorded in the ledger must be verified with active commands (`git status`, test runner execution, file inspection) before writing code.

3. **Prune Stale Intermediate Output**
   - Do not paste multi-hundred line build logs or raw database dumps into the conversation history.
   - Extract only the failing line, the specific exception message, and the immediate stack frame before updating the state anchor.

4. **Context Window Linting**
   - Use `skillforge lint-context` to ensure workspace instruction files (`AGENTS.md`, `CLAUDE.md`) remain under the 150-line ceiling:

```bash
skillforge lint-context --project . --strict
```
