# SkillForge

SkillForge is a dependency-light MVP for creating, validating, discovering, installing, and packaging portable `SKILL.md` files. The universal format uses YAML frontmatter with required `name` and `description` fields followed by Markdown instructions.

Documentation: https://gintingism.github.io/skillforge/

## Install

```powershell
python -m pip install agent-skillforge
```

The CLI is exposed as `skillforge` (or `python -m skillforge.cli` in an environment configured for module execution).

## Usage

```powershell
skillforge create code-review --description "Review code carefully" --directory .\skills\code-review
skillforge validate .\skills\code-review\SKILL.md
skillforge validate .\skills\code-review\SKILL.md --json
skillforge pack .\skills\code-review --output .\code-review.zip
skillforge search review --registry .\.skillforge
skillforge install code-review --registry .\.skillforge --project .
```

The local registry stores skills as `<registry>/<name>/SKILL.md`. The explicit built-in registry ships seven skills and acts as fallback after configured local skills. The registry interface is intentionally abstract so a GitHub-backed implementation can be added without changing CLI consumers. Installation detects `.github` for Copilot, `.claude` for Claude Code, and `.cursor` for Cursor. Copilot receives `.github/copilot-instructions.md`; Claude Code receives `.claude/skills/<name>/SKILL.md`; Cursor receives `.cursor/skills/<name>/SKILL.md`.

`validate --json` emits machine-readable validation results without changing human-readable output or exit codes.

## MCP server

SkillForge uses the official MCP Python SDK. Install project dependencies, then configure an MCP client to run:

```json
{
  "mcpServers": {
    "skillforge": {
      "command": "skillforge",
      "args": ["serve-mcp"],
      "env": {
        "SKILLFORGE_REGISTRY_PATH": "C:\\path\\to\\.skillforge"
      }
    }
  }
}
```

The server exposes `skill://{name}` resources and read-only tools `search_skills`, `get_skill`, and `validate_skill`. Protocol messages use stdout; server logs use stderr. `server.json` contains the same launcher metadata.

## Development

```powershell
python -m pip install -e ".[dev]"
python -m pytest
python -m mypy src
mkdocs build --strict
```
