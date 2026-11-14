# Changelog

## 0.7.0 - 2026-11-14

- Added `skillforge policy` (`--init`, `--check`) and `skillforge audit --policy` supporting `.skillforge-policy.yaml` rule disablement, severity overrides, minimum score thresholds, and scoped suppressions with mandatory reasons and expiration dates.
- Extended `skillforge audit-mcp` with `MCP-005` (MCP tool poisoning detection in tool descriptions and schemas), `MCP-006` (cross-server and built-in tool shadowing), and `MCP-007` (cross-server toxic flow detection across untrusted ingestion, sensitive access, and external egress).
- Added `skillforge scan-all` for workspace and optional `--home` machine-wide auto-discovery across IDE skills and MCP config files with consolidated JSON and SARIF v2.1.0 output.
- Added `skillforge check`, `skillforge update`, and `skillforge migrate-lock` for upstream lockfile update checks, security-gated upgrades, and `vercel-labs/skills` (`skills-lock.json`) migration.
- Added `skillforge telemetry` offline JSONL usage ledger wired into `serve-mcp` (`get_skill`, `get_skill_resource`) to surface invocation counts, loaded token spend, and unused startup pointer overhead while honoring `DO_NOT_TRACK=1`.

## 0.6.0 - 2026-11-13

- Added `skillforge sbom` CycloneDX v1.6 AIBOM and SPDX v2.3 Software Bill of Materials generator inventorying agent skills, SHA-256 digests, token budgets, MCP servers (`mcp.json`), and mapped security vulnerabilities.
- Added `skillforge provenance` and `skillforge verify-provenance` generating and verifying SLSA v1.0 Provenance (`https://slsa.dev/provenance/v1`) and in-toto v1 Statements (`https://in-toto.io/Statement/v1`) with HMAC-SHA256 attestation.
- Added `skillforge graph` skill dependency graph analyzer and topological resolver detecting circular dependencies (`DEP-001`), missing skills (`DEP-002`), and `allowed-tools` privilege escalation (`DEP-003`), plus transitive token profiling and Mermaid diagram export.
- Added `skillforge sync-rules` universal context rule synchronizer compiling `AGENTS.md` into `.cursor/rules/00-core.mdc`, `CLAUDE.md`, `.cursorrules`, `.windsurfrules`, and `.clinerules` with CI drift detection (`SYNC-001`) and contradictory directive scanning (`SYNC-002`).

## 0.5.0 - 2026-11-12

- Added `skillforge firewall-mcp` inline zero-trust JSON-RPC security firewall and traffic inspector blocking prompt injections (`FW-001`), shell smuggling (`FW-002`), credential traversal (`FW-003`), SSRF (`FW-004`), and unauthorized tools (`FW-006`) while automatically redacting leaked secrets (`FW-005`).
- Added `skillforge bench` multi-model semantic trigger benchmark matrix evaluating Precision, Recall, F1-Score, and False Positive Rate across `claude-sonnet-router`, `gemini-flash-router`, and `gpt-strict-router`.
- Added `skillforge refactor-progressive` automated progressive disclosure slicer with deterministic semantic and code-block preservation verification.
- Added `skillforge run-sandboxed` zero-trust capability jail runner blocking outbound network sockets, subprocess creation, sensitive host reads, and out-of-jail writes.
- Added `skillforge lsp` Language Server Protocol 3.17 daemon over stdio for real-time editor diagnostics, hover token analysis, and frontmatter completions.
- Added `skillforge keygen`, `skillforge sign`, and `skillforge verify-signature` for HMAC-SHA256 cryptographic attestation of skill packages and `skillforge.lock`.
- Added `skillforge search-remote` and `skillforge index` for community skill discovery, repository indexing, and automatic security audit gates on `skillforge install`.
- Added `skillforge tui` interactive Rich terminal dashboard for visual context token budget allocation and security grade reporting.
- Added security rules `SEC-007` through `SEC-017` (Python AST taint analyzer, allowed-tools scope enforcer, persistent memory/git hook poisoning, lethal trifecta compound risk, obfuscation/hex payloads, fork bombs/resource abuse, unpinned package installs) and `skillforge audit --sandbox`.
- Added `skillforge audit-mcp` configuration auditor (`MCP-001` through `MCP-004`) and `skillforge lint-context` instruction file linter (`CTX-001` through `CTX-004`).
- Expanded built-in standard skill catalog to 37 production-grade skills (all scoring 100/100).

## 0.4.2 - 2026-11-02

- Added OASIS SARIF v2.1.0 report generation to `skillforge audit --sarif <file.sarif>` for direct integration with GitHub Code Scanning.
- Added `skillforge import-openapi` command to convert OpenAPI 3.0, 3.1, and Swagger 2.0 specifications (JSON and YAML) into progressive disclosure skill packages.
- Added `skillforge test` command and testing harness supporting `evals/evals.json` test suites for trigger accuracy, positive activation, and negative suppression assertions.
- Added `skillforge optimize` context budget optimizer that refactors oversized `SKILL.md` documents exceeding `QUAL-003` into clean progressive disclosure references.
- Updated composite GitHub Action (`action.yml`) with native `sarif` parameter for automated security scanning in pull requests.

## 0.4.1 - 2026-11-01

- Added `skillforge badge` command to generate official verified shields.io badges for skill repositories (Markdown, HTML, JSON).
- Added official composite GitHub Action (`action.yml`) for automated security auditing and token budgeting on Pull Requests.
- Added automated VHS tape script (`demo.tape`) for recording terminal workflow GIFs.
- Added Hacker News Show HN, Reddit, and X/Twitter launch execution playbook in `docs/LAUNCH_PLAYBOOK.md`.
- Revamped `README.md` with zero-install `uvx` quickstart, comparison benchmark table, and verified badges.
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
