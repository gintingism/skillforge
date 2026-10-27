# MCP Server

SkillForge uses the official Python MCP SDK with protocol-safe stdio transport.

## Client Configuration

```json
{
  "mcpServers": {
    "skillforge": {
      "command": "skillforge",
      "args": ["serve-mcp"],
      "env": {
        "SKILLFORGE_REGISTRY_PATH": ".skillforge"
      }
    }
  }
}
```

If `SKILLFORGE_REGISTRY_PATH` is omitted, it defaults to `.skillforge` in the current working directory.
Packaged built-in skills remain available as a fallback. Local entries take precedence for duplicate names.

## Exposed API

### Resources
- `skill://{name}`: Reads a validated `SKILL.md` document.

### Tools
- `search_skills(query: str, limit: int = 50)`: Search names and descriptions across local and built-in registries.
- `get_skill(name: str)`: Returns the complete `SKILL.md` content (bounded to 25,000 characters).
- `get_skill_resource(name: str, resource_path: str)`: Reads a bundled progressive-disclosure file (such as `references/mechanics.md` or `scripts/run.py`) from a skill package on demand.
- `validate_skill(content: str)`: Validates frontmatter and schema without disk writes.
- `audit_skill(content: str)`: Audits raw skill content for prompt injections, zero-width unicode obfuscation, and dangerous shell patterns.

Protocol messages strictly use stdout; diagnostics and server logs stream to stderr.
