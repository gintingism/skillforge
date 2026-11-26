# Changelog

## 0.10.0 - 2026-11-25

- Added **Anti-Bypass Scanner Hardening** (`SEC-018` through `SEC-021`) closing Trail of Bits / CSA 2026 scanner bypass vectors: whitespace/newline padding inflation (`SEC-018`), precompiled bytecode and hidden binaries (`.pyc`, `.pyo`, `.wasm`, `.class`, `.beam`, `SEC-019`), ZIP-backed document/archive and SVG indirection (`.docx`, `.xlsx`, `.pptx`, `.zip`, `.svg`, `SEC-020`), and cipher/split-stream obfuscation plus Levenshtein typosquatting (`SEC-021`).
- Added **Native MCP `io.modelcontextprotocol/skills` Extension (SEP-2640)** (`skills_list`, `skills_get`, `read_skill_directory`, `get_server_capabilities`, `skill://{name}/SKILL.md`, and `skillforge mcp-manifest [--verify]`) with deterministic SHA-256 per-file manifests and 512-file / 16 MiB cap enforcement.
- Tightened **AAIF `agentskills.io` Strict 6-Field Validation** (`validate --strict-spec`) to enforce the 6 allowed top-level frontmatter fields, length limits, and non-portable Claude dynamic syntax checks, plus added `skillforge normalize` to auto-migrate custom fields under `metadata:`.
- Added **Live MCP Introspection, MCP Apps (`MCP-011`), Server Cards & Streamable-HTTP Firewall** (`audit-mcp --live`, `audit-mcp --server-card`, and `firewall-mcp --http-upstream` with stateless MCP `2026-07-28` `Mcp-Method`/`Mcp-Name` header smuggling protection).
- Added **Agent Plugins 1.0 Auditor (`skillforge audit-plugin`, `HOOK-001`–`HOOK-004`)**, **Skill Packs (`skillforge pack-bundle init|audit|install`)**, and **Multi-Target / Multi-Event Hooks** (`skillforge hooks --target claude,cursor,gemini,codex --events PreToolUse,PostToolUse,UserPromptSubmit` + `--check-response`).
- Added **A2A v1.0 Agent Card Auditor & Ed25519 JWS Signer** (`skillforge audit-a2a`, `A2A-001`–`A2A-005`) and **Sigstore Bundle v0.3 Keyless OIDC + Rekor Attestation** (`sign --sigstore`, `verify-signature --sigstore-bundle`, `provenance --sigstore`).
- Added **`.pre-commit-hooks.yaml`**, **Custom YAML/YARA-Style Rule Packs** (`audit --rules`), and **Opt-in Prompt-Hardened LLM Semantic Judge** (`audit --llm-judge`).

## 0.9.0 - 2026-11-24

- Added **MCP Tool Rug-Pull Lockfile** (`MCP-008`, `skillforge audit-mcp --pin-lock` / `--verify-lock`) pinning deterministic SHA-256 digests of MCP server commands, endpoints, and embedded tool schemas (`mcp-lock.json`) to detect post-install mutations.
- Added **MCP 2026-07-28 Remote Transport & OAuth 2.1 Checks** (`MCP-009` blocking unencrypted non-localhost `http://`/`ws://` endpoints; `MCP-010` flagging hardcoded `Authorization` / `X-API-Key` headers and deprecated OAuth Dynamic Client Registration).
- Added **OWASP Agentic Top 10 (2026) `ASI01`–`ASI10` Compliance Mapping** across `AuditFinding.owasp_asi`, JSON/terminal reports, OASIS SARIF v2.1.0 rule/result tags, and CycloneDX v1.6 AIBOM vulnerabilities (including real-time MCP server vulnerability scoring in `skillforge sbom`).
- Added **Strict `agentskills.io` Specification Mode** (`skillforge validate --strict-spec`) enforcing lowercase hyphen-only names, directory name alignment, 5,000-token / 500-line body caps, and string-only metadata values.
- Added **Agent Session `PreToolUse` Security Hook** (`skillforge hooks --init` and `--check-payload`) installing and running `MCPFirewall` tool-invocation guards in `.claude/settings.json`.
- Expanded workspace/global skill discovery, `scan-all`, `lint-context`, and `SEC-013` memory poisoning rules to cover `.opencode/skills`, `.roo/skills`, `.codex/skills`, `GEMINI.md`, `.roomodes`, and `.claude/settings.json`, and upgraded the composite GitHub Action (`action.yml`) with `policy`, `audit-mcp`, `mcp-lock`, `sync-rules-check`, and `lint-context` inputs.

## 0.8.0 - 2026-11-18

- Added asymmetric **Ed25519** keypair generation, signing, and verification across skill packages, `skillforge.lock`, and SLSA v1.0 `in-toto` provenance (`skillforge keygen --algorithm ed25519`, `skillforge sign --algorithm ed25519`, `skillforge provenance --algorithm ed25519 --key-file`, `skillforge verify-provenance --key-file`).
- Extended `skillforge run-sandboxed` to execute `.sh`/`.bash` and `.js`/`.mjs` scripts alongside Python, with automatic Linux `bwrap` (`--unshare-net`, read-only rootfs) OS-level isolation when available.
- Added `skillforge firewall-mcp --wrap-config <mcp.json>` to idempotently wrap stdio MCP server entries through the inline security firewall.
- Extended `skillforge serve-mcp` with `audit_mcp_config` and `check_policy` tools plus `--transport` (`stdio`, `sse`, `streamable-http`).
- Added ecosystem adapters for **OpenCode** (`.opencode/skills`), **Roo Code** (`.roo/skills`), **Codex CLI** (`.codex/skills`), and **Gemini CLI** (`.gemini/skills`), and added `gemini` (`GEMINI.md`) and `copilot` (`.github/copilot-instructions.md`) targets to `skillforge sync-rules`.
- Added `.github/workflows/ci.yml` and root `.skillforge-policy.yaml` dogfooding `pytest`, `mypy`, policy-gated `skillforge audit`, `skillforge sync-rules --check`, and `skillforge lint-context` across Python 3.11 and 3.12.

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
