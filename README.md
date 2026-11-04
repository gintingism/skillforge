<div align="center">

# SkillForge

**Universal package manager, security auditor, and context token profiler for portable AI agent skills (`SKILL.md`).**

[![PyPI version](https://img.shields.io/pypi/v/agent-skillforge.svg?color=blue&style=flat-square)](https://pypi.org/project/agent-skillforge/)
[![Python versions](https://img.shields.io/pypi/pyversions/agent-skillforge.svg?style=flat-square)](https://pypi.org/project/agent-skillforge/)
[![CI](https://img.shields.io/github/actions/workflow/status/gintingism/skillforge/publish.yml?style=flat-square)](https://github.com/gintingism/skillforge/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Audited by SkillForge](https://img.shields.io/badge/Security-SkillForge%20Passed-2ea44f?logo=shield&style=flat-square)](https://github.com/gintingism/skillforge)
[![HOL Guard](https://img.shields.io/endpoint?url=https%3A%2F%2Fhol.org%2Fapi%2Fregistry%2Fbadges%2Fplugin%3Fslug%3Dgintingism%252Fskillforge%26metric%3Drelease)](https://hol.org/registry/plugins/gintingism%2Fskillforge?utm_source=hol_marketplace&utm_medium=plugins_badge&utm_campaign=plugins&utm_content=gintingism%2Fskillforge&ref=plugin-author-78e0507b)

Audit, package, test, and profile portable agent skills across Claude Code, Cursor, Google Antigravity, Windsurf, GitHub Copilot, and Cline.

</div>

---

## Quickstart

Run commands directly without installing using `uvx` or `pipx`:

```bash
# 1. Check workspace health, token load, and installed skills
uvx agent-skillforge doctor

# 2. Audit a skill directory for prompt injections and malicious patterns
uvx agent-skillforge audit ./skills/my-skill

# 3. Profile token cost: startup pointer cost vs on-demand body cost
uvx agent-skillforge budget

# 4. Generate an official verified security badge
uvx agent-skillforge badge ./skills/my-skill
```

Or install permanently with `pip`:
```bash
pip install agent-skillforge
```

---

## Why SkillForge

As AI coding assistants adopt the open `SKILL.md` format, two practical problems appear in day-to-day use:

1. **Supply-chain security:** Community skills are plain executable instructions. Unreviewed skills can contain prompt injections, invisible zero-width unicode characters, or exfiltrate local credentials (`~/.ssh`, `~/.aws/credentials`).
2. **Context token burn:** Skills load description text into the model prompt on every turn. Unoptimized skills waste hundreds of tokens before the agent starts thinking, increasing API costs and reducing reasoning quality.

| Capability | Manual Copy-Paste | General Skill CLIs | SkillForge |
| :--- | :---: | :---: | :---: |
| **Runtime** | None | Node.js / npm | **Python 3.11+ (`pip` / `uvx`)** |
| **Offline Security Audit** | No | No | **100% Local Pattern & AST Scanner** |
| **Prompt Injection Check** | No | No | **Built-in (`SEC-002`)** |
| **Hidden Unicode / Bidi Scans** | No | No | **Built-in (`SEC-001`)** |
| **Python AST & Taint Tracking** | No | No | **Built-in (`SEC-008`)** |
| **Link Phishing / Spoofing** | No | No | **Built-in (`SEC-007`)** |
| **Context Token Profiler** | No | No | **Built-in (`skillforge budget`)** |
| **Trigger Eval Testing** | No | No | **Built-in (`skillforge test`)** |
| **Context Budget Optimizer** | No | No | **Built-in (`skillforge optimize`)** |
| **OpenAPI / Swagger Importer** | No | No | **Built-in (`skillforge import-openapi`)** |
| **OASIS SARIF v2.1.0 Export** | No | No | **Built-in (`--sarif` for Code Scanning)** |
| **Reproducible Lockfile** | No | Manifest only | **SHA-256 + Pinned Git Commit SHA** |
| **Native MCP Server & Agent Plugins 1.0** | No | Partial | **Built-in (`mcp.json`, `serve-mcp`)** |
| **Supported Assistants** | Manual | Single target | **Claude, Cursor, Antigravity, Windsurf, Cline, Codex, Copilot** |

---

## Workflows

### 1. Diagnose your workspace (`doctor`)

Inspect all installed skills across your project or global directories (Claude Code, Cursor, Antigravity, Windsurf, Cline) for security issues, token load, and broken pointers:

```bash
# Diagnose active project
skillforge doctor

# Diagnose global user configuration
skillforge doctor --global
```
```text
SkillForge Doctor Diagnostic (Project: 4 skills)
  Health Status:        PASSED (All Healthy)
  Startup Context Load: ~340 tokens (Every turn discovery cost)
  On-Demand Body Cost:  ~2180 tokens
  Security Findings:    0 Critical, 0 High, 0 Total
```

### 2. Audit skills before running them (`audit`)

Scan an individual skill, a directory of skills, or the entire repository for prompt injections, AST taint flows, hidden payloads, and broken pointers:

```bash
# Audit an individual skill
skillforge audit ./skills/my-new-skill

# Audit an entire collection directory or project root
skillforge audit ./skills
skillforge audit .
```
```text
Audit Report: my-new-skill
Status: PASSED (Score: 100/100)
Context Load: 60 pointer tokens | 520 body tokens (27 lines)
Total Findings: 0
```

The auditor checks for:
- **Invisible & Bidi Unicode (SEC-001):** Zero-width spaces (`\u200B`, `\uFEFF`), homoglyphs, and bidirectional control characters (`\u202E`, `\u2066`) used to conceal prompt instructions or alter execution order.
- **Prompt Injections (SEC-002):** Directives like `"ignore previous instructions"`, `"system override"`, or attempts to bypass safety guards. Quoted defensive examples are flagged as `MEDIUM`, while imperative commands remain `CRITICAL`.
- **Dangerous Shell Commands (SEC-003):** Patterns like `curl ... | bash`, base64-decoded execution, and suspicious outbound transmission.
- **Credential Path Access (SEC-004):** Unauthorized access to `~/.ssh`, `~/.aws/credentials`, or local environment files.
- **Exfiltration Endpoints (SEC-005):** Outbound transmission to capture services (`webhook.site`, `pipedream.net`, `requestbin.net`) or environment variable exfiltration.
- **Hardcoded Secrets (SEC-006):** Embedded API keys and provider tokens (`ghp_`, `github_pat_`, `sk-ant-`, `AIzaSy`, `AKIA`).
- **Markdown Link Spoofing (SEC-007):** Mismatched visible URL hostnames and target URL destinations hiding deceptive redirects.
- **Python AST & Taint Analysis (SEC-008):** Structural AST inspection of bundled Python scripts for `eval()`, `exec()`, `subprocess(..., shell=True)`, `pickle.loads()`, and environment-to-network taint flows.
- **Unrestricted Tool Scope (SEC-009):** Wildcard tool permissions (`*`, `Bash(*)`) in `allowed-tools` frontmatter.
- **Trigger Quality (QUAL-001):** Ensures descriptions specify concrete activation conditions.
- **Directory Alignment (QUAL-002):** Ensures folder name matches the frontmatter `name`.
- **Progressive Disclosure Budget (QUAL-003):** Flags `SKILL.md` bodies exceeding 500 lines or ~5,000 tokens so secondary reference material is moved to `references/`.
- **Broken Disclosure Pointers (QUAL-004):** Checks that cited `references/...` and `scripts/...` files exist on disk.
- **Applicability Hijacking (QUAL-006):** Flags overbroad trigger descriptions claiming all tasks.

For CI pipelines, pass `--strict` to fail on warnings, `--json` for automation, or `--sarif` for GitHub Code Scanning:
```bash
# Audit an individual skill
skillforge audit ./skills/my-new-skill --sarif results.sarif

# Or audit the entire workspace
skillforge audit . --sarif results.sarif
```

### 3. Profile startup token load (`budget`)

Model-invoked skills keep their `name` and `description` in the prompt on every turn. Measure how many tokens your skills consume before triggering:

```bash
skillforge budget
# Inspect built-in catalog:
skillforge budget --builtin
```
```text
Context Budget Profile (22 skills)
  Always-Loaded Startup Pointer Cost: ~1305 tokens
  On-Demand SKILL.md Body Cost:       ~7483 tokens
  Disclosed Resources Cost:           ~349 tokens
```

### 4. Test trigger accuracy with eval suites (`test`)

Verify that your skill description triggers on relevant user requests, ignores unrelated prompts, and satisfies keyword constraints:

```bash
# Generate a starter evals/evals.json test suite
skillforge test ./skills/my-skill --init

# Run test cases
skillforge test ./skills/my-skill
```
```text
Running evals for 'my-skill' (4 test cases)...
  [PASS] trigger_positive_core_my_skill: "Please help me with my-skill following our workflow."
  [PASS] trigger_positive_task: "I need to execute a task: my skill workflow description"
  [PASS] suppress_negative_unrelated_math: "Calculate the Fibonacci sequence for n=30 in Python."
  [PASS] suppress_negative_greeting: "Hello there, what is the weather like in Tokyo today?"

Result: PASSED (4/4 passed)
```

Use `--json` in CI to ensure changes to `description` do not break activation behavior.

### 5. Optimize bloated skills with progressive disclosure (`optimize`)

When a skill exceeds the 500-line or 5,000-token limit (`QUAL-003`), extract secondary guides into `references/` while keeping concise pointers in `SKILL.md`:

```bash
# Refactor an oversized skill in-place
skillforge optimize ./skills/bloated-api-skill --max-lines 400

# Or write to a new destination folder
skillforge optimize ./skills/bloated-api-skill -o ./skills/clean-api-skill
```
```text
Optimized 'bloated-api-skill':
  Lines:  680 -> 240 (440 lines saved)
  Tokens: ~6200 -> ~2100 (4100 tokens saved)
  Extracted References:
    - references/database-guidelines.md
    - references/api-endpoints-manual.md
  Destination: ./skills/clean-api-skill
  Audit Verification: PASSED
```

### 6. Convert OpenAPI / Swagger specs into skills (`import-openapi`)

Convert an OpenAPI 3.0, 3.1, or Swagger 2.0 specification (JSON or YAML) into a portable skill package:

```bash
skillforge import-openapi ./openapi.yaml --output ./skills
```
```text
Successfully imported 'petstore-api' into skills/petstore-api
  SKILL.md:               28 lines (~320 body tokens)
  endpoints.md reference: ~1850 tokens
```

The resulting package places an executive summary in `SKILL.md` and moves full endpoint schemas to `references/endpoints.md`, keeping prompt overhead low.

### 7. Generate a verified security badge (`badge`)

Show users that your skill passed security auditing. Generate a markdown or HTML badge for your repository:

```bash
skillforge badge ./my-skill
```
```markdown
[![Audited by SkillForge](https://img.shields.io/badge/SkillForge-Security%20Passed%20100%2F100-2ea44f?logo=shield&style=flat-square)](https://github.com/gintingism/skillforge)
```

### 8. Install directly from GitHub (`add`)

Pull skills from remote repositories with security auditing and commit pinning:

```bash
# Pull a specific skill from a repository
skillforge add anthropics/skills:pdf

# Pin to an exact release tag or branch
skillforge add anthropics/skills:pdf@v1.2.0

# Install from a custom repository
skillforge add gintingism/skillforge:systematic-debugging
```

SkillForge audits the skill, installs it into detected assistant directories, and records the SHA-256 digest and Git commit SHA in `skillforge.lock`.

### 9. Verify skill integrity and detect drift (`verify`)

Check installed skills against `skillforge.lock` in CI/CD or local environments without making network requests. Detects file tampering, missing dependencies, or unmanaged skills:

```bash
# Verify active project
skillforge verify

# Emit JSON for automation
skillforge verify --json
```
```text
  OK       clean-code (sha256: 4f3a9e1208bc...)
  OK       systematic-debugging (sha256: 8a91bc7d01fe...)

Verification PASSED: 2 skill(s) match skillforge.lock.
```

### 10. Compare changes before updating (`diff`)

Inspect diffs between local skills and upstream repositories, or compare two skill versions:

```bash
skillforge diff ./skills/my-skill
skillforge diff my-skill gintingism/skillforge:my-skill
```

### 11. Manage installed skills (`list` & `remove`)

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

Remove a skill from all detected assistants and update your lockfile:
```bash
skillforge remove antislop-code
```

### 12. Create and package skills (`create` & `pack`)

Scaffold a single skill file or a full package directory with scripts and references:

```bash
# Single skill file
skillforge create api-design -d "Design REST/gRPC APIs. Use when creating new backend endpoints."

# Full package with scripts/ and references/
skillforge create db-migrator -d "Run Postgres migrations safely. Use when writing SQL schema updates." --full
```

Pack a skill into a zip archive, or unpack one safely with path traversal protection:
```bash
skillforge pack ./db-migrator --output ./db-migrator.zip
skillforge unpack ./db-migrator.zip --output ./skills
```

---

## Automate in CI/CD (GitHub Action)

Add SkillForge to your GitHub Actions workflow to audit pull requests, enforce token budgets, and upload SARIF reports to GitHub Code Scanning:

```yaml
name: Audit Agent Skills
on: [pull_request, push]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Run SkillForge Security & Token Linter
        uses: gintingism/skillforge@main
        with:
          path: './skills'
          strict: 'true'
          budget: 'true'
          sarif: 'skillforge-findings.sarif'

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'skillforge-findings.sarif'
```

---

## Model Context Protocol (MCP) Integration

SkillForge includes a native MCP server conforming to the Agent Plugins 1.0 specification (configured via `mcp.json`), so coding agents can inspect, search, and audit skills during their development loop:

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
- `get_skill_resource(name, resource_path)`: Read disclosed `references/*` or `scripts/*` files on demand with path traversal protection.
- `validate_skill(content)`: Test frontmatter syntax in memory.
- `audit_skill(content)`: Audit a raw skill document for prompt injections, AST taint flows, and malicious patterns.
- `skill://{name}`: Resource URI for direct document retrieval.

---

## Supported Assistants

SkillForge detects your assistant environment and places skills in the canonical directory:

| Assistant | Detected by | Installed location |
| :--- | :--- | :--- |
| **Google Antigravity / Gemini CLI** | `.gemini/` | `.gemini/config/skills/<name>/SKILL.md` |
| **Claude Code & Claude Desktop** | `.claude/` | `.claude/skills/<name>/SKILL.md` |
| **Cursor** | `.cursor/` | `.cursor/skills/<name>/SKILL.md` |
| **Windsurf** | `.windsurf/`, `.windsurfrules` | `.windsurf/skills/<name>/SKILL.md` |
| **Cline / Roo-Code** | `.cline/`, `.roomodes` | `.cline/skills/<name>/SKILL.md` |
| **Universal Agents (`npx skills` / Codex / OpenCode)** | `.agents/` | `.agents/skills/<name>/SKILL.md` |
| **AGENTS.md Catalog** | `AGENTS.md` | Appended to `AGENTS.md` catalog |
| **GitHub Copilot** | `.github/` | `.github/copilot-instructions.md` |

To install a skill globally to your user profile instead of the current project, add `--global` (`-g`):
```bash
skillforge install systematic-debugging --global
```

---

## Built-in Skills (22 Zero-Slop Skills)

SkillForge ships with 22 practical engineering skills to address common agent failure modes identified in benchmark research:

### Code Quality, Security & Performance
- `supply-chain-sentinel`: Check package existence, registry age, and run CVE audits (`pip-audit`, `npm audit`) before adding dependencies.
- `secret-sanitizer`: Pre-commit git diff auditor that prevents API keys, private tokens, and credentials from leaking.
- `contract-test-generator`: Property-based testing and contract boundary fuzz tests (Hypothesis, fast-check) to verify invariants.
- `blast-radius-containment`: Upstream reference tracing and a strict file touch budget before modifying shared code or public APIs.
- `security-threat-modeler`: Trust-boundary mapping, IDOR/BOLA object-level authorization checks, SSRF validation, and injection sink verification.
- `performance-profiler`: Baseline-first latency (`p50`/`p95`/`p99`), N+1 query detection, and algorithmic complexity verification before optimizing.
- `antislop-code`: Comment hygiene and anti-overengineering filters that remove trivial narrative comments and prevent speculative generality.
- `spec-driven-development`: Schema-first API design and red-green verification loops before writing application logic.
- `zero-downtime-migration`: Four-phase Expand-Contract pattern for non-breaking database schema and API evolutions.

### Autonomous Loop Stability & Debugging
- `systematic-debugging`: Four-phase diagnosis protocol (Reproduce, Isolate, Hypothesize, Surgical Patch) before touching code.
- `cognitive-loop-breaker`: Three-strikes circuit breaker that forces a hard `git restore` and hypothesis invalidation when stuck in repetitive edit-fail loops.
- `flaky-test-isolation`: Stress-reproduction loop (50x iterations) and diagnosis protocol for race conditions, clock skew, and state leakage.
- `runtime-api-verification`: Interactive signature introspection (`inspect`, `dir()`, compiler definitions) to prevent hallucinated arguments.

### Context Efficiency & Multi-Agent Operations
- `skill-architect`: Multi-file progressive disclosure guide for authoring low-token `SKILL.md`, `AGENTS.md`, and `CLAUDE.md` files.
- `caveman`: Terse technical communication mode that reduces token spend while preserving exact paths, commands, and errors.
- `context-compactor`: Structured state distillation and active hypothesis ledgers for long-running agent threads nearing context limits.
- `mcp-tool-designer`: Type-safe schema design, idempotent hints, token boundaries, and stderr error separation for MCP servers.
- `agent-observability`: OpenTelemetry tracing standards, step timing, and 16KB payload truncation boundaries.
- `human-in-the-loop`: Three-tier permission model separating read-only queries from irreversible actions.
- `summarize`: Executive engineering summaries with exact file and line citations.
- `tavily-search`: Authoritative primary-source technical research with cross-verification.
- `self-improving-agent`: Error recording loop that turns recurring bugs into durable project rules.

---

## Contributing & Development

- **Package Distribution:** Published on PyPI as [`agent-skillforge`](https://pypi.org/project/agent-skillforge/).
- **Launch Guidelines:** See [`docs/LAUNCH_PLAYBOOK.md`](docs/LAUNCH_PLAYBOOK.md) for distribution notes.
- **Local Development:**
  ```bash
  git clone https://github.com/gintingism/skillforge.git
  cd skillforge
  python -m pip install -e ".[dev]"
  pytest
  mypy src
  ```

---

## Listed on HOL Plugins

[SkillForge on HOL Plugins](https://hol.org/registry/plugins/gintingism%2Fskillforge?utm_source=hol_marketplace&utm_medium=plugins_badge&utm_campaign=listed_link&utm_content=gintingism%2Fskillforge) shows the latest scan, trust score and release evidence for this plugin.

---

License: [MIT](LICENSE)
