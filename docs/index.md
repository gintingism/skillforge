# SkillForge Documentation

SkillForge is a package manager, security auditor, and MCP server for portable agent skills (`SKILL.md`).

## What it does

- **Portable Format:** Follows the open `SKILL.md` specification from the Agentic AI Foundation (AAIF), supporting directory packages with `scripts/`, `references/`, and `assets/`.
- **Remote Git Registry:** Install skills directly from GitHub repositories with `skillforge add owner/repo:skill`.
- **Security Auditor:** Scan skills for prompt injections, hidden zero-width unicode, and dangerous shell exfiltration with `skillforge audit`.
- **Multi-Assistant Adapters:** Installs skills automatically into Google Antigravity, Claude Code, Cursor, Windsurf, Cline, universal `AGENTS.md`, and GitHub Copilot.
- **Built-in Skills:** Ships 11 production-grade engineering workflows without fluff.
- **MCP Server:** Exposes skills and security scanning to any MCP-compatible client.

## Quick Installation

```bash
pip install agent-skillforge
```

For local development:

```bash
pip install -e ".[dev,docs]"
```

See [CLI Reference](cli.md) for available commands and [MCP Server](mcp.md) for client configuration.
