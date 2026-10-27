# Architecture

SkillForge separates portable skill specifications from assistant-specific directory layouts, providing a clean boundary between skill authoring, security auditing, and editor installation.

## High-Level Architecture

```text
┌────────────────────────────────────────────────────────┐
│           Portable SKILL.md Directory Package          │
│    (YAML Frontmatter + Markdown + scripts/ + refs/)    │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
               ┌─────────────────────────┐
               │  SkillPackage & Model   │
               │   (Schema Validation)   │
               └────────────┬────────────┘
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
┌───────────────────────┐       ┌───────────────────────┐
│     SkillAuditor      │       │       Registry        │
│  - Zero-width unicode │       │  - BuiltinRegistry    │
│  - Prompt injections  │       │  - LocalRegistry      │
│  - Script exfil check │       │  - GitRemoteRegistry  │
└───────────────────────┘       └───────────┬───────────┘
                                            │
                      ┌─────────────────────┴─────────────────────┐
                      ▼                                           ▼
          ┌───────────────────────┐                   ┌───────────────────────┐
          │     CLI Interface     │                   │      MCP Server       │
          │ (add, audit, list, rm)│                   │(search, get, validate,│
          └───────────┬───────────┘                   │     audit_skill)      │
                      │                               └───────────────────────┘
                      ▼
          ┌───────────────────────────────────────────────────┐
          │                Assistant Adapters                 │
          │ - ClaudeCodeAdapter (.claude/skills/)             │
          │ - CursorAdapter (.cursor/skills/)                 │
          │ - AntigravityAdapter (.gemini/config/skills/)     │
          │ - WindsurfAdapter (.windsurf/skills/)             │
          │ - ClineAdapter (.cline/skills/)                   │
          │ - AgentsMarkdownAdapter (AGENTS.md)               │
          │ - CopilotAdapter (.github/copilot-instructions.md)│
          └───────────────────────────────────────────────────┘
```

## Component Boundaries

1. **Document Model (`skill.py`):**
   - Strictly enforces the AAIF `agentskills.io` specification.
   - `Skill`: Represents the parsed metadata (`name`, `description`, `license`, `compatibility`, `metadata`, `allowed-tools`) and body text.
   - `SkillPackage`: Represents the multi-file directory bundle containing execution helper scripts (`scripts/`), in-depth reference documentation (`references/`), and static assets (`assets/`).

2. **Security Engine (`security.py`):**
   - Evaluates packages and raw content before execution or installation.
   - Decoupled from network and filesystem access so it can be called synchronously in CLI commands or asynchronously via MCP tools.

3. **Registries (`registry.py`):**
   - `LocalRegistry`: Manages on-disk directories under `.skillforge/`.
   - `BuiltinRegistry`: Ships 16 battle-tested engineering workflows packaged with the library.
   - `GitRemoteRegistry`: Clones or updates remote Git/GitHub repositories into `~/.skillforge/cache/` using shallow clones.
   - `CompositeRegistry`: Merges multiple registry backends with explicit priority order.

4. **Adapters (`adapters.py`):**
   - Isolated installation targets. Each adapter knows how to detect its target environment, install single files or complete directory bundles, list active skills, and cleanly remove unneeded skills.
