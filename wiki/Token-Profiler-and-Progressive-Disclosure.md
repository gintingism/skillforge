# Token Profiler and Progressive Disclosure

This guide explains how SkillForge profiles token overhead and helps author skills that minimize context window consumption.

---

## The Economics of Agent Context

In modern AI coding assistants (such as Claude Code, Cursor, and Antigravity), all installed skills register their metadata into the system prompt. This creates a two-phase token loading model:

1. **Phase 1: Startup Pointer (Always Loaded):** The skill `name` and `description` are loaded into the prompt on **every single conversational turn**. If you have 30 installed skills and each has a 100-token description, your agent wastes 3,000 tokens per turn before reading your actual request. Over a 50-turn conversation, that amounts to 150,000 wasted input tokens.
2. **Phase 2: On-Demand Body (Loaded When Triggered):** The full instructions in `SKILL.md` are only loaded when the user prompt matches the skill's activation trigger.

```text
Turn 1: [System Prompt + 30 Skill Descriptions] + User: "Hello"
Turn 2: [System Prompt + 30 Skill Descriptions] + User: "Fix this bug" -> Activates 'systematic-debugging'
Turn 3: [System Prompt + 30 Skill Descriptions + systematic-debugging Body] + User: "Next step"
```

SkillForge provides specialized tools to measure and enforce this two-phase model.

---

## Measuring Token Overhead with `budget`

Run `skillforge budget` to inspect the token footprint of your project's active skills:

```bash
skillforge budget
```

Sample output:
```text
Context Budget Profile (4 skills)
  Always-Loaded Startup Pointer Cost: ~240 tokens
  On-Demand SKILL.md Body Cost:       ~3100 tokens
  Disclosed Resources Cost:           ~850 tokens

Skill Breakdown:
  [systematic-debugging] 
    Pointer: 52 tokens | Body: 810 tokens | References: 420 tokens
  [secret-sanitizer]     
    Pointer: 64 tokens | Body: 720 tokens | References: 0 tokens
```

To profile SkillForge's standard library of 29 built-in skills:
```bash
skillforge budget --builtin
```

---

## Progressive Disclosure Standard

To prevent context bloat, SkillForge enforces the **Progressive Disclosure Standard** (`QUAL-003`):

- **Rule 1:** A `SKILL.md` file must not exceed 500 lines or approximately 5,000 tokens.
- **Rule 2:** Deep manuals, API specifications, and extensive checklists must be extracted to the `references/` subdirectory.
- **Rule 3:** Executable helper tools and automation scripts must be placed in `scripts/`.
- **Rule 4:** The `SKILL.md` file must cite reference files clearly so the agent only reads them when strictly necessary.

### Directory Structure of an Optimized Skill Package

```text
my-database-skill/
├── SKILL.md                  # Concise overview, triggers, and core workflow (<500 lines)
├── scripts/
│   └── run_migration.py      # Executable automation tool
└── references/
    ├── sql-anti-patterns.md  # Deep reference manual read only on demand
    └── index-guide.md        # Technical index reference
```

---

## Automated Refactoring with `optimize`

If an existing skill exceeds the 500-line budget, use `skillforge optimize` to automatically extract secondary sections into the `references/` folder:

```bash
# Refactor an oversized skill in-place
skillforge optimize ./skills/bloated-api-skill --max-lines 400

# Or write the optimized package to a separate directory
skillforge optimize ./skills/bloated-api-skill -o ./skills/clean-api-skill
```

Output:
```text
Optimized 'bloated-api-skill':
  Lines:  680 -> 240 (440 lines saved)
  Tokens: ~6200 -> ~2100 (4100 tokens saved)
  Extracted References:
    - references/database-guidelines.md
    - references/api-endpoints-manual.md
  Destination: ./skills/clean-api-skill
  Audit Verification: PASSED
```

---

## Context File Linter (`lint-context`)

In addition to individual skills, root-level instruction files like `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, and `.windsurfrules` are injected into context on every turn. 

Use `skillforge lint-context` to identify bloat, generic buzzwords, and redundant directives:

```bash
skillforge lint-context
```

Output:
```text
Context Linter: project-root
Status: WARNINGS DETECTED
Files Scanned: 2 (AGENTS.md, CLAUDE.md)
Context Overhead: ~1840 tokens across 210 lines

Findings:
  [HIGH] CTX-001 (CLAUDE.md:162): Context file has 162 lines (exceeds 150-line ceiling).
  [LOW]  CTX-003 (AGENTS.md:14): Generic buzzword 'seamless' found; replace with concrete operational constraints.
```
