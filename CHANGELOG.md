# Changelog

## 0.2.0 - 2026-10-27

- Full compliance with the open `SKILL.md` directory package specification (AAIF / Agentic AI Foundation).
- Added multi-file `SkillPackage` support preserving `scripts/`, `references/`, and `assets/`.
- Added `skillforge audit` security scanner detecting invisible zero-width unicode (SEC-001), prompt injections (SEC-002), dangerous shell/exfiltration commands (SEC-003), and credential access (SEC-004).
- Added `skillforge add` for direct installation and security auditing from remote GitHub/Git repositories.
- Added `skillforge list` and `skillforge remove` commands for managing active skills across assistants.
- Added new assistant adapters: Google Antigravity / Gemini CLI, Windsurf, Cline / Roo-Code, and universal `AGENTS.md`.
- Added support for `--global` assistant installations.
- Expanded built-in skills to 16 zero-slop production workflows, addressing critical SWE-bench failure modes (`blast-radius-containment`, `cognitive-loop-breaker`, `flaky-test-isolation`, `runtime-api-verification`, `zero-downtime-migration`).
- Added `audit_skill` tool to the official MCP server.
- Updated packaging to PEP 639 standards and added workflow_dispatch / tag triggers to GitHub Actions publish workflow.

## 0.1.0 - 2026-10-03

- Added universal `SKILL.md` parsing and validation.
- Added local registry and Copilot/Claude adapters.
- Added Typer CLI commands.
- Added official MCP server with resources and read-only tools.
- Added test coverage gate and strict type checking.
- Added built-in skills, explicit built-in registry fallback, and Cursor adapter support.
- Distribution name is `agent-skillforge`; CLI command remains `skillforge`.
