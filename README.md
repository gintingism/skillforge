# SkillForge

SkillForge is a dependency-light MVP for creating, validating, discovering, installing, and packaging portable `SKILL.md` files. The universal format uses YAML frontmatter with required `name` and `description` fields followed by Markdown instructions.

## Install

```powershell
python -m pip install -e .
```

The CLI is exposed as `skillforge` (or `python -m skillforge.cli` in an environment configured for module execution).

## Usage

```powershell
skillforge create code-review --description "Review code carefully" --directory .\skills\code-review
skillforge validate .\skills\code-review\SKILL.md
skillforge pack .\skills\code-review --output .\code-review.zip
skillforge search review --registry .\.skillforge
skillforge install code-review --registry .\.skillforge --project .
```

The local registry stores skills as `<registry>/<name>/SKILL.md`. The registry interface is intentionally abstract so a GitHub-backed implementation can be added without changing CLI consumers. Installation detects `.github` for Copilot and `.claude` for Claude; Copilot receives `.github/copilot-instructions.md`, while Claude receives `.claude/skills/<name>/SKILL.md`.

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
```
