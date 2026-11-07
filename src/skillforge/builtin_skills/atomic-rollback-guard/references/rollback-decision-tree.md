# Rollback Decision Tree

This reference outlines explicit thresholds for when an agent must abandon a code change and trigger an immediate hard rollback.

## Core Thresholds

| Condition | Action | Rationale |
| :--- | :--- | :--- |
| **Attempt 1 Fails** | 1 targeted refinement allowed | Minor typos or missing imports can be adjusted once. |
| **Attempt 2 Fails with Same Error** | Immediate Hard Rollback | The initial hypothesis is disproven. Continuing leads to patch compounding. |
| **Attempt 2 Fails with New Errors** | Immediate Hard Rollback | Edits caused cascading regressions across the test suite. |
| **Syntax Errors in Unrelated Files** | Immediate Hard Rollback | File mutation logic damaged adjacent AST blocks. |

## Rollback Command Matrix

Depending on the checkpoint method selected at task startup:

### Stash-Based Checkpoints
```bash
# Revert working tree to stash checkpoint
git checkout -- .
git clean -fd

# Drop temporary checkpoint
git stash drop
```

### Git Commit Checkpoints (Recommended for Multi-File Refactoring)
```bash
# Reset working tree and index to checkpoint commit
git reset --hard CHECKPOINT_SHA
```

### Single-File Revert
```bash
# Revert single file to HEAD
git checkout HEAD -- path/to/failing_file.py
```

## Post-Rollback Invalidation Rule

Once rollback finishes:
1. Do not immediately retry the same code changes.
2. Record in chat: *"Hypothesis rejected: [explanation]. Workspace restored to clean baseline."*
3. Read the relevant code from scratch before proposing an alternative approach.
