# Getting Started with SkillForge

This guide covers installing SkillForge, running your first workspace diagnosis, auditing third-party agent skills, and locking dependencies for reproducible team environments.

---

## Prerequisites

- **Python:** 3.11 or newer.
- **Operating Systems:** Linux, macOS, and Windows.
- **Supported Coding Assistants:** Claude Code, Cursor, Google Antigravity / Gemini CLI, Windsurf, Cline / Roo-Code, and GitHub Copilot.

---

## Installation

### Ephemeral Execution (No Installation Required)

If you use `uv` or `pipx`, you can run SkillForge commands directly without modifying your global Python environment:

```bash
# Using uvx
uvx agent-skillforge doctor

# Using pipx
pipx run agent-skillforge doctor
```

### Permanent Installation

Install SkillForge directly from PyPI into your active Python environment:

```bash
pip install agent-skillforge
```

Verify your installation:

```bash
skillforge --help
```

---

## Core Daily Workflows

### 1. Diagnose Your Project Workspace

Run `doctor` to scan your repository for installed skills, token overhead, and potential security issues:

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

Before executing a community skill, run `audit` to ensure it contains no prompt injections, unauthorized file reads, or malicious scripts:

```bash
# Audit an individual skill directory
skillforge audit ./skills/my-new-skill

# Audit an entire collection directory or repository root
skillforge audit .

# Run with strict mode in CI/CD pipelines
skillforge audit . --strict --sarif results.sarif
```

### 3. Profile Token Overhead

Agent skills declare a `name` and `description` in their YAML frontmatter. These descriptions are loaded into the prompt on every conversational turn. Check your token overhead:

```bash
# Profile installed skills in active project
skillforge budget

# Profile SkillForge's built-in standard catalog
skillforge budget --builtin
```

### 4. Lock and Verify Dependencies

To ensure skills are not modified or tampered with across different machines, SkillForge generates a cryptographically signed `skillforge.lock` lockfile recording exact SHA-256 digests and Git commit hashes:

```bash
# Add a remote skill from GitHub and update lockfile
skillforge add anthropics/skills:pdf@v1.2.0

# Verify local skills against lockfile in CI (zero network calls)
skillforge verify
```

If any file within a managed skill has been altered, `verify` exits with a non-zero status code:

```text
  ERROR    tampered-skill: SHA-256 mismatch
           expected: 4f3a9e1208bc...
           actual:   8e910214a1fa...
Verification FAILED: 1 skill(s) failed integrity check.
```

---

## Common CLI Command Summary

| Command | Description | Common Flags |
| :--- | :--- | :--- |
| `skillforge doctor` | Inspect workspace health, active skills, and context load. | `--global` |
| `skillforge audit <path>` | Security and quality audit of a skill or folder. | `--strict`, `--json`, `--sarif <file>` |
| `skillforge budget` | Profile startup pointer versus on-demand body token usage. | `--builtin`, `--json` |
| `skillforge test <path>` | Run trigger evaluation suites against sample prompts. | `--init`, `--json` |
| `skillforge optimize <path>` | Extract bloated skills into progressive disclosure packages. | `--max-lines <n>`, `-o <out>` |
| `skillforge import-openapi <path>` | Convert Swagger / OpenAPI specs into skills. | `--output <dir>` |
| `skillforge lint-context` | Scan `AGENTS.md`, `CLAUDE.md`, `.cursorrules` for bloat. | `--strict`, `--json` |
| `skillforge add <repo:skill>` | Install a skill from GitHub with audit and commit pin. | `--global`, `--target <assistant>` |
| `skillforge verify` | Verify installed skills against `skillforge.lock`. | `--json` |
| `skillforge list` | List active skills across all detected assistants. | `--all` |
| `skillforge remove <name>` | Remove a skill and update lockfile. | `--global` |
| `skillforge create <name>` | Scaffold a new skill template. | `-d <desc>`, `--full` |
| `skillforge pack <path>` | Package a skill directory into a protected zip archive. | `--output <file>` |
| `skillforge unpack <archive>` | Unpack an archive safely with path traversal defense. | `--output <dir>` |
| `skillforge serve-mcp` | Start standard MCP server for agent integration. | `--stdio` |
