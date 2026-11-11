# Getting Started with SkillForge

This guide covers installing SkillForge, running workspace diagnostics, auditing third-party agent skills, and locking dependencies for predictable team environments.

---

## System Requirements

* **Python:** 3.11 or newer.
* **Operating Systems:** Linux, macOS, and Windows.
* **Supported Assistants:** Claude Code, Cursor, Google Antigravity, Windsurf, Cline, Codex, and GitHub Copilot.

---

## Installation

### Ephemeral Execution (No Installation Required)

If you use `uv` or `pipx`, you can run SkillForge commands directly without altering your global Python packages:

```bash
# Using uvx
uvx agent-skillforge doctor

# Using pipx
pipx run agent-skillforge doctor
```

### Standard Installation

Install SkillForge directly from PyPI into your active Python environment:

```bash
pip install agent-skillforge
```

Verify that the CLI is accessible:

```bash
skillforge --help
```

---

## Essential Workflows

### 1. Diagnose Your Project Workspace

Run `doctor` to inspect your repository for installed skills, token overhead, and security issues:

```bash
# Inspect local repository
skillforge doctor

# Inspect global user configuration (~/.claude, ~/.gemini, ~/.cursor)
skillforge doctor --global
```

Sample output:
```text
SkillForge Doctor Diagnostic (Project: 4 skills)
  Health Status:        PASSED (All Healthy)
  Startup Context Load: ~340 tokens (Every turn discovery cost)
  On-Demand Body Cost:  ~2180 tokens
  Security Findings:    0 Critical, 0 High, 0 Total
```

### 2. Audit Skills Before Running Them

Before executing a community skill, run `audit` to ensure it contains no prompt injections, credential harvesting, or destructive commands:

```bash
# Audit an individual skill directory
skillforge audit ./skills/my-new-skill

# Run dynamic sandbox execution testing (blocks network and subprocesses)
skillforge audit ./skills/my-new-skill --sandbox

# Audit MCP server configuration files
skillforge audit-mcp ./mcp.json

# Run with strict mode and output SARIF for GitHub Code Scanning
skillforge audit . --strict --sarif results.sarif
```

### 3. Profile Context Token Overhead

Agent skills declare a name and description in their YAML frontmatter. These descriptions are loaded into the prompt on every conversational turn. Check your token overhead:

```bash
# Profile installed skills in active project
skillforge budget

# Profile SkillForge's built-in standard catalog
skillforge budget --builtin
```

### 4. Interactive Terminal Dashboard

To view token allocation across 8K, 32K, and 128K context windows alongside security scores in a visual console:

```bash
# Snapshot overview
skillforge tui --static

# Live dashboard with periodic refresh
skillforge tui --watch
```

### 5. Lock, Sign, and Verify Dependencies

To ensure skills are not modified or tampered with across different machines, SkillForge generates a lockfile and supports cryptographic signatures:

```bash
# Add a remote skill from GitHub with automatic security verification
skillforge add anthropics/skills:pdf@v1.2.0

# Generate a 256-bit cryptographic release key
skillforge keygen --out skill.key

# Sign your skill package directory
skillforge sign ./skills/my-skill --key-file skill.key

# Verify integrity and detect tampering
skillforge verify-signature ./skills/my-skill --key-file skill.key

# Verify lockfile in CI pipelines (zero network calls)
skillforge verify
```

---

## Complete CLI Command Reference

| Command | Description | Typical Options |
| :--- | :--- | :--- |
| `skillforge doctor` | Inspect workspace health, active skills, and context load. | `--global` |
| `skillforge audit <path>` | Security and quality audit of a skill or folder. | `--sandbox`, `--strict`, `--sarif <file>` |
| `skillforge audit-mcp <file>` | Security audit of Model Context Protocol configurations. | `--json` |
| `skillforge budget` | Profile startup pointer vs on-demand body token usage. | `--builtin`, `--json` |
| `skillforge test <path>` | Run trigger evaluation suites against sample prompts. | `--init`, `--json` |
| `skillforge optimize <path>` | Extract bloated skills into progressive disclosure packages. | `--max-lines <n>`, `-o <out>` |
| `skillforge import-openapi <path>` | Convert Swagger and OpenAPI specifications into skills. | `--output <dir>` |
| `skillforge lint-context` | Scan instruction files (AGENTS.md, CLAUDE.md) for bloat. | `--strict`, `--json` |
| `skillforge search-remote [query]` | Search the remote community skills catalog. | `--tag <tag>` |
| `skillforge index [path]` | Scan and index a repository into the discovery cache. | `--url <url>` |
| `skillforge lsp` | Run Language Server Protocol daemon for editor feedback. | Standard I/O |
| `skillforge keygen` | Generate a 256-bit cryptographic signing key. | `--out <file>` |
| `skillforge sign <path>` | Sign a skill package or lockfile with HMAC-SHA256. | `--key-file <file>`, `--signer <id>` |
| `skillforge verify-signature <path>` | Verify manifest digests and signature authenticity. | `--key-file <file>` |
| `skillforge tui` | Open the interactive terminal dashboard. | `--static`, `--watch` |
| `skillforge add <spec>` | Install a skill from GitHub with audit and commit pinning. | `--global`, `--skip-audit` |
| `skillforge install <name>` | Install a local or built-in skill with security gate. | `--min-score <n>`, `--insecure` |
| `skillforge verify` | Verify installed skills against `skillforge.lock`. | `--json` |
| `skillforge list` | List active skills across all detected assistants. | `--all` |
| `skillforge remove <name>` | Remove an installed skill and update lockfile. | `--global` |
| `skillforge create <name>` | Scaffold a new skill template. | `-d <desc>`, `--full` |
| `skillforge pack <path>` | Package a skill directory into a zip archive. | `--output <file>` |
| `skillforge unpack <archive>` | Unpack an archive safely with path traversal defense. | `--output <dir>` |
| `skillforge serve-mcp` | Start standard MCP server for agent integration. | Standard I/O |
