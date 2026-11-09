# Persistent Memory & Git Hook Audit Checklist

## High-Risk Persistence Targets (OWASP ASI06)

| File / Directory | Load Timing | Threat Vector |
| :--- | :--- | :--- |
| `CLAUDE.md` / `AGENTS.md` | Every session startup | Silent rule overrides, weakened security checks, or spoofed build commands |
| `.cursorrules` / `.windsurfrules` | IDE workspace open | Background instruction injection triggered on file edit |
| `MEMORY.md` / `.claude/memory/` | Cross-session recall | Poisoned facts or fabricated API endpoints persisted from prior turns |
| `.git/hooks/pre-commit` | Every `git commit` | Arbitrary local shell execution when developer commits code |

## Review Checklist

1. **Zero Hidden Characters**: Confirm no zero-width spaces (`U+200B`) or bidirectional overrides (`U+202E`) exist in instruction files.
2. **No Remote Shell Pipelines**: Reject any instruction in `CLAUDE.md` or `AGENTS.md` that fetches remote scripts over HTTP.
3. **Explicit Provenance**: Every added convention in `AGENTS.md` must trace to an intentional developer decision rather than automated scrape output.
4. **Hook Integrity**: Ensure `.git/hooks/` scripts contain only known local linters (such as `skillforge audit` or `pytest`) and no outbound network requests.
