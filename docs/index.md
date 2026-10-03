# SkillForge

SkillForge manages portable `SKILL.md` files for AI coding assistants.

## What it provides

- Universal YAML-frontmatter skill model.
- Local registry with future registry backends.
- Copilot and Claude installation adapters.
- CLI commands for create, validate, search, install, and pack.
- MCP server exposing read-only skill resources and tools.

## Install

```powershell
python -m pip install skillforge
```

For source development:

```powershell
python -m pip install -e ".[dev,docs]"
```

## First skill

```powershell
skillforge create code-review --description "Review code carefully" --directory .\skills\code-review
skillforge validate .\skills\code-review\SKILL.md
skillforge pack .\skills\code-review --output .\code-review.zip
```

See [CLI](cli.md) for all commands and [MCP server](mcp.md) for client setup.
