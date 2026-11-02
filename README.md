<div align="center">

# SkillForge

**Universal package manager, security auditor, and context token profiler for portable AI agent skills (`SKILL.md`).**

[![PyPI version](https://img.shields.io/pypi/v/agent-skillforge.svg?color=blue&style=flat-square)](https://pypi.org/project/agent-skillforge/)
[![Python versions](https://img.shields.io/pypi/pyversions/agent-skillforge.svg?style=flat-square)](https://pypi.org/project/agent-skillforge/)
[![CI](https://img.shields.io/github/actions/workflow/status/gintingism/skillforge/publish.yml?style=flat-square)](https://github.com/gintingism/skillforge/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Audited by SkillForge](https://img.shields.io/badge/Security-SkillForge%20Passed-2ea44f?logo=shield&style=flat-square)](https://github.com/gintingism/skillforge)

*Write once. Audit locally. Deploy seamlessly across Claude Code, Cursor, Google Antigravity, Windsurf, Copilot, and Cline.*

</div>

---

## ⚡ 10-Second Quickstart (Zero-Install)

No Node.js, npm, or permanent installation required. Run directly with `uvx` or `pipx`:

```bash
# 1. Diagnose your workstation & assistant skills for security & bloat
uvx agent-skillforge doctor

# 2. Audit any local or community skill before executing it
uvx agent-skillforge audit ./skills/my-skill

# 3. Profile startup context token overhead vs on-demand body cost
uvx agent-skillforge budget

# 4. Generate an official verified badge for your skill repository
uvx agent-skillforge badge ./skills/my-skill
```

Or install permanently via `pip`:
```bash
pip install agent-skillforge
```

---

## 💡 Why SkillForge?

As AI coding assistants adopt the open `SKILL.md` format (standardized under the Agentic AI Foundation / AAIF), two major friction points have emerged:

1. **Supply-Chain & Prompt Injection Attacks:** Community skills are executable instruction sets. Unvetted skills can hide indirect prompt injections, Trojan Unicode characters, credential harvesters (`~/.ssh`, `~/.aws`), or command injections.
2. **Context Window & Token Burn:** Loading unoptimized skills burns hundreds of tokens on every turn before an agent even starts thinking, driving up API bills and degrading reasoning quality.

| Feature | Manual Copy-Paste | Node CLIs (`npx skills`) | **SkillForge** |
| :--- | :---: | :---: | :---: |
| **Language Runtime** | None | Requires Node.js / npm | **Pure Python (`uvx` / `pip`)** |
| **Offline Security Linter** | ❌ None | ⚠️ Cloud-dependent / SaaS | **✅ 100% Local Deterministic AST & Regex** |
| **Prompt Injection Detection** | ❌ None | ❌ No | **✅ Built-in (`SEC-002`)** |
| **Trojan Unicode & Bidi Scans** | ❌ None | ❌ No | **✅ Built-in (`SEC-001`, `SEC-005`)** |
| **Context Token Profiler** | ❌ None | ❌ No | **✅ Built-in (`skillforge budget`)** |
| **Reproducible Lockfile** | ❌ None | ⚠️ Loose | **✅ SHA-256 + Pinned Git Commit SHA** |
| **Native MCP Server** | ❌ None | ❌ No | **✅ Built-in (`skillforge serve-mcp`)** |
| **Assistant Targets** | Manual | Limited | **Claude, Cursor, Antigravity, Windsurf, Cline, Copilot** |

---

## 🛠️ Core Workflows

### 1. Diagnose your workspace (`doctor`)

Inspect all installed skills across your project or global workstation (Claude Code, Cursor, Antigravity, Windsurf, Cline) for security vulnerabilities, context window load, and broken pointers:

```bash
# Diagnose active project
skillforge doctor

# Diagnose all global machine skills
skillforge doctor --global
```
```text
SkillForge Doctor Diagnostic (Project: 4 skills)
  Health Status:        PASSED (All Healthy)
  Startup Context Load: ~340 tokens (Every turn discovery cost)
  On-Demand Body Cost:  ~2180 tokens
  Security Findings:    0 Critical, 0 High, 0 Total
```

### 2. Audit a skill before running it (`audit`)

Before letting an agent read and execute a skill, inspect it for hidden payloads, broken progressive disclosure links, and prompt injection:

```bash
skillforge audit ./skills/my-new-skill
```

Example output:
```text
Audit Report: my-new-skill
Status: PASSED (Score: 100/100)
Context Load: 60 pointer tokens | 520 body tokens (27 lines)
Total Findings: 0
```

What the auditor scans for:
- **Invisible Unicode (SEC-001):** Zero-width spaces (`\u200B`, `\uFEFF`), homoglyphs, and directional overrides used to hide prompt instructions from human code review.
- **Prompt Injections & Jailbreaks (SEC-002):** Directives like `"ignore previous instructions"`, `"system override"`, or attempts to disable safety guardrails. Quoted references in defensive guides are flagged as `MEDIUM`, while bare imperative commands remain `CRITICAL`.
- **Dangerous Shell Commands (SEC-003):** Script patterns like `curl ... | bash`, base64-decoded execution, and outbound data exfiltration.
- **Credential Path Access (SEC-004):** Unsanctioned attempts to access `~/.ssh`, `~/.aws/credentials`, or local environment secrets.
- **Invisible Bidi & Control Characters (SEC-005):** Trojan Source bidirectional control characters (`\u202E`, `\u2066`) that alter code execution order while displaying harmlessly.
- **Markdown Link Spoofing & Phishing (SEC-006):** Mismatched visual labels vs target URLs hiding malicious redirects.
- **Trigger Quality (QUAL-001):** Verifies model-invoked descriptions contain explicit activation conditions.
- **Directory Alignment (QUAL-002):** Ensures folder name matches YAML `name`.
- **Progressive Disclosure Budget (QUAL-003):** Flags `SKILL.md` bodies exceeding 500 lines or ~5,000 tokens so heavy references are moved to `references/`.
- **Broken Disclosure Pointers (QUAL-004):** Verifies cited `references/...` or `scripts/...` exist.

For CI pipelines, pass `--strict` to fail on any warning, `--json` for automation, or `--sarif` for GitHub Code Scanning:
```bash
# Export standard OASIS SARIF v2.1.0 report
skillforge audit ./skills/my-new-skill --sarif results.sarif
```

### 3. Profile your project's context token budget (`budget`)

Every model-invoked skill keeps its `name` and `description` in the startup context window on every turn. Measure how much context your skills consume before they even trigger:

```bash
skillforge budget
# Or inspect the built-in catalog:
skillforge budget --builtin
```
```text
Context Budget Profile (22 skills)
  Always-Loaded Startup Pointer Cost: ~1305 tokens
  On-Demand SKILL.md Body Cost:       ~7483 tokens
  Disclosed Resources Cost:           ~349 tokens
```

### 4. Test skill trigger accuracy and assertions (`test`)

Verify that your skill description triggers on relevant user prompts, ignores unrelated requests, and respects keyword constraints using a deterministic test suite:

```bash
# Initialize a starter evals/evals.json test suite
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

Use `--json` in CI to verify that changes to `description` do not break activation accuracy.

### 5. Optimize bloated skills with progressive disclosure (`optimize`)

When a skill exceeds the 500-line or 5,000-token progressive disclosure budget (`QUAL-003`), extract heavy reference sections into `references/` while keeping concise pointers in `SKILL.md`:

```bash
# Refactor an oversized skill directory in-place
skillforge optimize ./skills/bloated-api-skill --max-lines 400

# Or output to a fresh destination folder
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

### 6. Convert OpenAPI / Swagger to a portable skill (`import-openapi`)

Convert an existing REST API specification (OpenAPI 3.0, 3.1, or Swagger 2.0 in JSON or YAML) into a progressive disclosure skill package without running external scripts:

```bash
skillforge import-openapi ./openapi.yaml --output ./skills
```
```text
Successfully imported 'petstore-api' into skills/petstore-api
  SKILL.md:               28 lines (~320 body tokens)
  endpoints.md reference: ~1850 tokens
```

The resulting package contains an executive overview in `SKILL.md` and detailed endpoint schemas in `references/endpoints.md`, keeping turn-by-turn context overhead low.

### 7. Generate an official verified badge (`badge`)

Show users that your skill is clean, secure, and audited. Generate an official badge for your skill repository:

```bash
skillforge badge ./my-skill
```
```markdown
[![Audited by SkillForge](https://img.shields.io/badge/SkillForge-Security%20Passed%20100%2F100-2ea44f?logo=shield&style=flat-square)](https://github.com/gintingism/skillforge)
```

### 8. Grab a skill directly from GitHub (`add`)

Pull skills directly from remote Git repositories with security auditing and reproducible commit pinning:

```bash
# Pull a specific skill from a GitHub repo
skillforge add anthropics/skills:pdf

# Pin to an exact release tag or branch
skillforge add anthropics/skills:pdf@v1.2.0

# Install from your team's repository
skillforge add gintingism/skillforge:systematic-debugging
```

SkillForge fetches the skill, audits its security, routes it to all detected assistant targets, and pins its SHA-256 digest + Git commit SHA into `skillforge.lock`.

### 9. Verify skill integrity and detect drift (`verify`)

Check installed skills against `skillforge.lock` in CI/CD or local environments without modifying files or making network requests. Detects file tampering, missing dependencies, or unmanaged skills:

```bash
# Verify active project
skillforge verify

# Output JSON for CI automation
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

To remove a skill from all detected assistants and update your lockfile:
```bash
skillforge remove antislop-code
```

### 12. Create and package your own skills (`create` & `pack`)

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

## 🤖 Automate in CI/CD (GitHub Action)

Add SkillForge to your GitHub Actions workflow to audit pull requests, enforce progressive disclosure budgets, and upload SARIF reports to GitHub Code Scanning:

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

## 🔌 Model Context Protocol (MCP) Integration

SkillForge includes a native MCP server so your coding agent can inspect, search, and audit skills autonomously during its development loop:

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
- `get_skill_resource(name, resource_path)`: Read disclosed `references/*` or `scripts/*` files on demand.
- `validate_skill(content)`: Test frontmatter syntax.
- `audit_skill(content)`: Audit a raw skill document for prompt injections and malicious patterns.
- `skill://{name}`: Resource URI for direct document retrieval.

---

## 🎯 Supported Assistants

SkillForge automatically detects your assistant environment and routes skills to the canonical directory:

| Assistant | Detected by | Installed location |
| :--- | :--- | :--- |
| **Google Antigravity / Gemini CLI** | `.gemini/` | `.gemini/config/skills/<name>/SKILL.md` |
| **Claude Code & Claude Desktop** | `.claude/` | `.claude/skills/<name>/SKILL.md` |
| **Cursor** | `.cursor/` | `.cursor/skills/<name>/SKILL.md` |
| **Windsurf** | `.windsurf/`, `.windsurfrules` | `.windsurf/skills/<name>/SKILL.md` |
| **Cline / Roo-Code** | `.cline/`, `.roomodes` | `.cline/skills/<name>/SKILL.md` |
| **Codex / Universal Agents** | `AGENTS.md`, `.agents/` | Appended to `AGENTS.md` catalog |
| **GitHub Copilot** | `.github/` | `.github/copilot-instructions.md` |

To install a skill globally to your user profile instead of the current project, add `--global` (`-g`):
```bash
skillforge install systematic-debugging --global
```

---

## 📦 Shipped Built-in Skills (22 Zero-Slop Skills)

SkillForge ships with 22 practical engineering skills designed to counteract common agent failure modes identified in benchmark research (SWE-bench, Snyk ToxicSkills, Skill-Inject):

### Code Quality, Security & Performance
- `supply-chain-sentinel`: Verify package existence, registry age, and run CVE audits (`pip-audit`, `npm audit`) before adding dependencies.
- `secret-sanitizer`: Pre-commit git diff auditor that prevents API keys, private tokens, and `.env` credentials from leaking.
- `contract-test-generator`: Property-based testing and contract boundary fuzz tests (Hypothesis, fast-check) to verify algebraic invariants.
- `blast-radius-containment`: Upstream reference tracing and a strict "file touch budget" before modifying shared code or public APIs.
- `security-threat-modeler`: Trust-boundary mapping, IDOR/BOLA object-level authorization checks, SSRF validation, and injection sink verification.
- `performance-profiler`: Baseline-first latency (`p50`/`p95`/`p99`), N+1 query detection, and algorithmic complexity verification before optimizing.
- `antislop-code`: Comment hygiene and anti-overengineering filters (removes trivial narrative comments, stops speculative generality).
- `spec-driven-development`: Schema-first API design and red-green verification loops before writing application logic.
- `zero-downtime-migration`: Four-phase Expand-Contract pattern for non-breaking database schema and API payload evolutions.

### Autonomous Loop Stability & Debugging
- `systematic-debugging`: Disciplined four-phase diagnosis protocol (Reproduce, Isolate, Hypothesize, Surgical Patch) before touching code.
- `cognitive-loop-breaker`: Three-strikes circuit breaker that forces a hard `git restore` and hypothesis invalidation when stuck in repetitive edit-fail loops.
- `flaky-test-isolation`: Stress-reproduction loop (50x iterations) and diagnosis protocol for race conditions, clock skew, and state leakage.
- `runtime-api-verification`: Interactive signature introspection (`inspect`, `dir()`, compiler definitions) to prevent hallucinated kwargs.

### Context Efficiency & Multi-Agent Operations
- `skill-architect`: Multi-file progressive disclosure guide (bundled with `references/mechanics.md`) for authoring low-token `SKILL.md`, `AGENTS.md`, and `CLAUDE.md` files.
- `caveman`: Terse, high-density technical communication mode that reduces token spend while preserving exact paths, commands, and errors.
- `context-compactor`: Structured state distillation and active hypothesis ledgers for long-running agent threads nearing context limits.
- `mcp-tool-designer`: Type-safe schema design, idempotent hints, token boundaries, and stderr error separation for MCP servers.
- `agent-observability`: OpenTelemetry tracing standards, step timing, and 16KB payload truncation boundaries.
- `human-in-the-loop`: Three-tier permission model separating read-only queries from irreversible actions.
- `summarize`: Executive engineering summaries with exact file and line citations.
- `tavily-search`: Authoritative primary-source technical research with cross-verification.
- `self-improving-agent`: Error recording loop that turns recurring bugs into durable project rules.

---

## 🚀 Community & Contributing

- **Distribution:** Published on PyPI as [`agent-skillforge`](https://pypi.org/project/agent-skillforge/).
- **Launch Playbook:** See [`docs/LAUNCH_PLAYBOOK.md`](docs/LAUNCH_PLAYBOOK.md) for community distribution and launch guidelines.
- **Development:**
  ```bash
  git clone https://github.com/gintingism/skillforge.git
  cd skillforge
  python -m pip install -e ".[dev]"
  pytest
  mypy src
  ```

License: [MIT](LICENSE)
