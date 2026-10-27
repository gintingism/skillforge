# SkillForge Documentation

SkillForge is a package manager, security auditor, and MCP server for portable agent skills (`SKILL.md`).

## What it does

- **Portable Format:** Follows the open `SKILL.md` specification from the Agentic AI Foundation (AAIF), supporting directory packages with `scripts/`, `references/`, and `assets/`.
- **Remote Git Registry:** Install skills directly from GitHub repositories with `skillforge add owner/repo:skill`.
- **Security & Progressive Disclosure Auditor:** Scan skills for prompt injections, hidden zero-width unicode, shell exfiltration, broken `references/` or `scripts/` pointers, and token budget sprawl with `skillforge audit`.
- **Context Budget Profiler:** Measure startup pointer token cost vs on-demand body token cost across your installed skills with `skillforge budget`.
- **Cryptographic Lockfile & Team Sync:** Pin SHA-256 package digests in `skillforge.lock` and deterministically sync across machines with `skillforge sync`.
- **Multi-Assistant Adapters:** Installs skills automatically into Google Antigravity, Claude Code, Cursor, Windsurf, Cline, universal `AGENTS.md`, and GitHub Copilot.
- **Built-in Skills:** Ships 19 production-grade engineering workflows without fluff.
- **MCP Server:** Exposes skills, progressive disclosure resources (`references/`, `scripts/`), and security scanning to any MCP-compatible client.

## Quick Installation

```bash
pip install agent-skillforge
```

For local development:

```bash
pip install -e ".[dev,docs]"
```

See [CLI Reference](cli.md) for available commands and [MCP Server](mcp.md) for client configuration.
