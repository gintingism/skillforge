# MCP server

SkillForge uses the official Python MCP SDK and stdio transport.

## Client configuration

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

Set `SKILLFORGE_REGISTRY_PATH` to local registry root. Default is `.skillforge` in current working directory.
Packaged built-in skills remain available as fallback. Local entries take precedence for duplicate names.

## Exposed API

Resource template:

- `skill://{name}` reads one validated skill document.

Read-only tools:

- `search_skills(query, limit)` searches name and description.
- `get_skill(name)` returns complete `SKILL.md` content.
- `validate_skill(content)` validates content without writing files.

Protocol messages use stdout. Diagnostics use stderr. Search results are limited to 100 items. Skill documents are bounded to 25,000 characters.
