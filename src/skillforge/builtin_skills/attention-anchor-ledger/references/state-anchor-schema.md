# State Anchor Schema

## 20-Line Anchor Template

When managing long-horizon tasks, maintain this concise block at session milestones:

```markdown
### Active State Anchor
- Task Goal: [Single concise sentence stating acceptance criteria]
- Working Branch: [git branch name]
- Last Verified Commit: [git rev-parse --short HEAD]
- Test Suite Status: [e.g. 123 passed, 0 failed]
- Modified Files:
  - path/to/file_a.py (added feature logic)
  - path/to/file_b.py (updated unit test)
- Current Working Hypothesis: [Single sentence explaining current approach]
- Invariants & Constraints:
  1. No breaking API changes to public endpoints.
  2. Maintain 100% offline static audit pass rate.
  3. No unpinned package dependencies.
- Next Immediate Action: [Single verifiable step]
```

## Pruning Guidelines

1. **Delete Resolved Hypotheses**: Remove disproven theories from the ledger immediately once test execution invalidates them.
2. **Cap File Lists at 10 Entries**: If a refactor touches more than 10 files, summarize by module directory rather than listing every file individually.
3. **Reference Commit Hashes**: Link to commit SHAs rather than embedding full diffs in markdown responses.
