# Architecture Decision Record (ADR) Template

Use this structure when recording an architectural decision in `docs/adr/NNNN-title-with-hyphens.md`:

```markdown
# ADR-NNNN: [Short Noun Phrase Title]

- **Status:** Proposed | Accepted | Superseded by ADR-XXXX
- **Date:** YYYY-MM-DD

## Context
State the technical force, business constraint, or scaling bottleneck driving this decision in 3 to 5 sentences. Cite concrete metrics or codebase paths.

## Options Considered

### 1. [Option A Name]
- **Pros:** Concrete engineering benefits.
- **Cons:** Operational cost, failure modes, and schema lock-in.

### 2. [Option B Name]
- **Pros:** Concrete engineering benefits.
- **Cons:** Operational cost, failure modes, and schema lock-in.

## Decision
State the chosen option and the primary technical reason it won over the alternatives.

## Consequences & Rollback Plan
- What becomes easier or harder in the repository.
- Exact steps required to revert this decision if production assumptions fail.
```
