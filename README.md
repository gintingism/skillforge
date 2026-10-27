# SkillForge

A package manager and security linter for portable agent skills (`SKILL.md`).

If you use Claude Code, Cursor, Google Antigravity, Windsurf, or Copilot, you've probably noticed two problems with agent instructions:

1. **System prompt bloat:** Dumping every coding guideline, style guide, and workflow directly into your global system prompt burns tokens on every turn and muddles model reasoning.
2. **Third-party skill safety:** Community skills are executable instructions. Loading unverified `SKILL.md` files or running their bundled scripts without checking for prompt injection or data exfiltration is an open invite for supply-chain attacks.

SkillForge follows the open `SKILL.md` standard (established under the Agentic AI Foundation / AAIF). It gives you a clean way to find, security-audit, install, and bundle skills across whatever coding assistant you or your team use.

---

## Installation

From PyPI:

```bash
pip install agent-skillforge
```

To run directly as a module if preferred: `python -m skillforge`

---

## Core Workflows

### 1. Grab a skill directly from GitHub (`add`)

Instead of cloning a repo, finding the skill folder, and copying files manually:

```bash
# Pull a specific skill from a GitHub repo
skillforge add anthropics/skills:pdf

# Or from your own team's repository
skillforge add gintingism/skillforge:systematic-debugging
```

SkillForge fetches the skill, runs a security check against it, installs it into your project's active assistant folders, and pins it in `skillforge.lock`.

### 2. Audit a skill before running it (`audit`)

Before letting an agent read and execute a skill, inspect it for hidden payloads and prompt injection:

```bash
skillforge audit ./skills/my-new-skill
```

Example output:
```text
Audit Report: my-new-skill
Status: PASSED (Score: 100/100)
Total Findings: 0
```

What the auditor scans for:
- **Invisible Unicode (SEC-001):** Zero-width spaces (`\u200B`, `\uFEFF`), homoglyphs, and directional overrides used to hide prompt instructions from human code review.
- **Prompt Injections & Jailbreaks (SEC-002):** Directives like `"ignore previous instructions"`, `"system override"`, or attempts to disable safety guardrails.
- **Dangerous Shell Commands (SEC-003):** Script patterns like `curl ... | bash`, base64-decoded execution, and outbound data exfiltration.
- **Credential Path Access (SEC-004):** Unsanctioned attempts to access `~/.ssh`, `~/.aws/credentials`, or local environment secrets.
- **Trigger Quality (QUAL-001):** Checks whether descriptions contain explicit activation conditions for progressive disclosure.

For CI pipelines, pass `--strict` to fail on any warning, or `--json` for automation:
```bash
skillforge audit ./skills/my-new-skill --strict --json
```

### 3. Check what's installed in your project (`list` & `remove`)

See which skills are active across your editor targets:

```bash
skillforge list
```
```text
Installed Skills:
  [ClaudeCode]:
    - antislop-code
    - systematic-debugging
  [Cursor]:
    - antislop-code
    - systematic-debugging
```

To remove a skill from all detected assistants and update your lockfile:
```bash
skillforge remove antislop-code
```

### 4. Create and package your own skills (`create` & `pack`)

Scaffold a single skill file or a full directory package with scripts and reference docs:

```bash
# Standard skill file
skillforge create api-design -d "Design REST/gRPC APIs. Use when creating new backend endpoints."

# Full package with scripts/ and references/
skillforge create db-migrator -d "Run Postgres migrations safely. Use when writing SQL schema updates." --full
```

Pack it into a shareable zip archive (or unpack one safely with path traversal protection):
```bash
skillforge pack ./db-migrator --output ./db-migrator.zip
skillforge unpack ./db-migrator.zip --output ./skills
```

---

## Supported Assistants

SkillForge automatically detects which assistants your repository uses and places the skill files in the right folder:

| Assistant | Detected by | Installed location |
| :--- | :--- | :--- |
| **Google Antigravity / Gemini CLI** | `.gemini/` | `.gemini/config/skills/<name>/SKILL.md` |
| **Claude Code & Claude Desktop** | `.claude/` | `.claude/skills/<name>/SKILL.md` |
| **Cursor** | `.cursor/` | `.cursor/skills/<name>/SKILL.md` |
| **Windsurf** | `.windsurf/`, `.windsurfrules` | `.windsurf/skills/<name>/SKILL.md` |
| **Cline / Roo-Code** | `.cline/`, `.roomodes` | `.cline/skills/<name>/SKILL.md` |
| **Codex / Universal Agents** | `AGENTS.md`, `.agents/` | Appended to `AGENTS.md` catalog |
| **GitHub Copilot** | `.github/` | `.github/copilot-instructions.md` |

To install a skill to your user home directory instead of the current project, add `--global` (`-g`):
```bash
skillforge install systematic-debugging --global
```

---

## Shipped Built-in Skills

SkillForge ships with 16 practical engineering skills designed to counteract common agent failure modes identified in benchmark research (SWE-bench):

### Code Quality & Architectural Boundaries
- `blast-radius-containment`: Upstream reference tracing and a strict "file touch budget" before modifying shared code or public APIs.
- `antislop-code`: Comment hygiene and anti-overengineering filters (removes trivial narrative comments, stops speculative generality).
- `spec-driven-development`: Schema-first API design and red-green verification loops before writing application logic.
- `zero-downtime-migration`: Four-phase Expand-Contract pattern for non-breaking database schema and API payload evolutions.

### Autonomous Loop Stability & Debugging
- `systematic-debugging`: Disciplined four-phase diagnosis protocol (Reproduce, Isolate, Hypothesize, Surgical Patch) before touching code.
- `cognitive-loop-breaker`: Three-strikes circuit breaker that forces a hard `git restore` and hypothesis invalidation when stuck in repetitive edit-fail loops.
- `flaky-test-isolation`: Stress-reproduction loop (50x iterations) and diagnosis protocol for race conditions, clock skew, and state leakage.
- `runtime-api-verification`: Interactive signature introspection (`inspect`, `dir()`, compiler definitions) to prevent hallucinated kwargs.

### Context Efficiency & Multi-Agent Operations
- `caveman`: Terse, high-density technical communication mode that reduces token spend while preserving exact paths, commands, and errors.
- `context-compactor`: Structured state distillation and active hypothesis ledgers for long-running agent threads nearing context limits.
- `mcp-tool-designer`: Type-safe schema design, idempotent hints, token boundaries, and stderr error separation for MCP servers.
- `agent-observability`: OpenTelemetry tracing standards, step timing, and 16KB payload truncation boundaries.
- `human-in-the-loop`: Three-tier permission model separating read-only queries from irreversible actions.
- `summarize`: Executive engineering summaries with exact file and line citations.
- `tavily-search`: Authoritative primary-source technical research with cross-verification.
- `self-improving-agent`: Error recording loop that turns recurring bugs into durable project rules.

---

## Model Context Protocol (MCP) Integration

SkillForge can run as an MCP server so your agent can search, read, and audit skills during its workflow:

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

Exposed MCP tools:
- `search_skills(query, limit)`: Search local and built-in skill catalogs.
- `get_skill(name)`: Read the full `SKILL.md` instructions.
- `validate_skill(content)`: Test frontmatter syntax.
- `audit_skill(content)`: Audit a raw skill document for prompt injections and malicious patterns.
- `skill://{name}`: Resource URI for direct document retrieval.

---

## Publishing to PyPI

SkillForge is published to PyPI under the package name `agent-skillforge`.

### Prerequisites for GitHub Actions Deployment
1. Ensure your repository has Trusted Publishing configured on [PyPI](https://pypi.org/manage/account/publishing/):
   - **PyPI Project Name:** `agent-skillforge`
   - **Owner:** `gintingism`
   - **Repository:** `skillforge`
   - **Workflow name:** `publish.yml`
   - **Environment:** `pypi`
2. Bump the version in `pyproject.toml` (e.g. `0.2.0`).

### Triggering a Release
You can publish through any of these three methods:
- **Git tag:** `git tag v0.2.0 && git push origin v0.2.0`
- **GitHub Release:** Publish a new release in the GitHub UI.
- **Manual dispatch:** Go to the GitHub Actions tab → "Publish package" → click "Run workflow".

### Local build check
To test building distributions locally before releasing:
```bash
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
```

---

## Contributing & Development

```bash
git clone https://github.com/gintingism/skillforge.git
cd skillforge

python -m pip install -e ".[dev]"
pytest
mypy src
```

License: [MIT](LICENSE)
