# Architecture

SkillForge separates portable skill data from assistant-specific installation.

```text
SKILL.md
   |
   v
Skill model + validation
   |
   +--> LocalRegistry
   |       |
   |       +--> CLI
   |       +--> MCP server
   |
   +--> CopilotAdapter
   +--> ClaudeAdapter
```

`Registry` is an abstract boundary. Future GitHub-backed registries can implement it without changing skill consumers.

MCP tools receive a registry instance through `create_mcp_server`. Tests can inject a temporary local registry without network access.
