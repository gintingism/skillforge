# Git Worktree Cleanup Protocol

When working with parallel agent tasks or speculative fixes, dangling worktrees cause locked branches, stale index files, and git contention errors. Follow this protocol to clean up worktrees cleanly.

## 1. Inspect Active Worktrees

Always inspect existing worktree allocations before creating or pruning directories:

```bash
git worktree list
```

Identify the path, commit SHA, and branch associated with each worktree.

## 2. Check Uncommitted Work Before Removal

Never delete a worktree without verifying if intermediate work was committed or stashed:

```bash
git -C ../my-worktree status --porcelain
```

If modifications exist that need preservation:
```bash
git -C ../my-worktree commit -m "chore: checkpoint speculative fix"
```

## 3. Safe Worktree Pruning

To remove a worktree and unlock its working directory:

```bash
# Remove worktree registration and delete its directory
git worktree remove --force ../my-worktree

# Prune stale administrative worktree metadata
git worktree prune
```

## 4. Cleaning Stale Branches

After the worktree is removed, delete experimental branches if they are no longer needed:

```bash
# Safe delete (fails if unmerged)
git branch -d feature/my-isolated-patch

# Force delete if discarded deliberately
git branch -D feature/my-isolated-patch
```

## 5. Troubleshooting Worktree Lock Contention

If Git warns that a worktree is locked:

```bash
# Unlock the worktree
git worktree unlock ../my-worktree

# Then remove
git worktree remove --force ../my-worktree
```
