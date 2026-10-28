# Changelog

## 0.4.1 - 2026-10-28

- Added `skillforge verify` command to audit installed skills against `skillforge.lock` for file drift, tampering, or missing packages without modifying files.
- Added reproducible Git commit SHA pinning in `skillforge.lock` and `GitRemoteRegistry` with support for `@<ref>` in remote specs.
- Fixed path traversal vulnerability in `skillforge remove` and adapter `remove()` methods (`_checked_name` guard).
- Blocked Git option injection and exotic transport smuggling in `GitRemoteRegistry` by validating URLs and refs with `--` argument separation.
- Made `CopilotAdapter` non-destructive using `<!-- skillforge:<name>:start/end -->` marker blocks, preserving user-authored team instructions.
- Refined `QUAL-004` to ignore markdown code fences, preventing documentation examples from being falsely flagged as missing reference files.
- Tightened `_TRIGGER_PATTERN` with word boundaries `\b` to avoid false trigger matches on words like "information".

## 0.4.0 - 2026-10-28

- Added `skillforge doctor` command for deep workstation diagnostics across all detected assistant targets.
- Added `skillforge diff` command to compare local skills with remote upstream repositories.
- Added security rule `SEC-005` (invisible bidi / control character detection) and `SEC-006` (markdown link spoofing & credential harvesting detection).
- Shipped 3 new production-grade built-in engineering skills: `antislop-code`, `spec-driven-development`, and `supply-chain-sentinel` (22 total).

## 0.3.0 - 2026-10-27

- Added `skillforge budget` context token budget profiler measuring always-loaded startup pointer cost vs on-demand body cost.
- Added progressive disclosure quality rules: `QUAL-003` (token/line budget), `QUAL-004` (broken pointers), and `QUAL-006` (applicability hijacking).
- Added `skillforge sync` command with deterministic SHA-256 integrity verification via `skillforge.lock`.
- Shipped 3 new built-in skills: `secret-sanitizer`, `contract-test-generator`, and `performance-profiler` (19 total).

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
