# Security Rules and Hardening

This document provides the full specification for SkillForge's security and quality rules. Every rule is deterministic, runs 100% offline, and maps directly to known supply-chain attack vectors in agentic environments.

---

## Security Rules Matrix (SEC-001 to SEC-011)

| Rule ID | Name | Severity | Attack Vector Addressed |
| :--- | :--- | :--- | :--- |
| **SEC-001** | Invisible & Bidi Unicode | CRITICAL | Zero-width characters (`\u200B`, `\uFEFF`) and bidirectional overrides (`\u202E`, `\u2066`) used to inject invisible instructions or reverse display order. |
| **SEC-002** | Prompt Injections | CRITICAL / MEDIUM | Direct jailbreak attempts (`ignore previous instructions`, `system override`). Quoted examples are scored as MEDIUM; direct imperatives are CRITICAL. |
| **SEC-003** | Dangerous Shell Commands | CRITICAL | Arbitrary remote execution pipelines (`curl ... \| bash`, `irm ... \| iex`), base64 decoded execution, and raw reverse shells. |
| **SEC-004** | Credential Path Access | HIGH | Direct access or harvesting of local credentials (`~/.ssh`, `~/.aws/credentials`, `.env`, `id_rsa`). |
| **SEC-005** | Exfiltration Endpoints | HIGH | Outbound data dispatch to public request catcher services (`webhook.site`, `pipedream.net`, `requestbin.net`) or environment token exfiltration. |
| **SEC-006** | Hardcoded Secrets | HIGH | Leaked API keys and platform tokens (`ghp_`, `github_pat_`, `sk-ant-`, `AIzaSy`, `AKIA`). |
| **SEC-007** | Markdown Link Spoofing | MEDIUM | Link descriptions displaying a trusted domain while the target URL points to a different deceptive destination. |
| **SEC-008** | Python AST & Taint Flow | HIGH | Python scripts invoking dynamic code evaluation (`eval`, `exec`), shell executions (`subprocess(..., shell=True)`), or flowing environment secrets into HTTP sinks. |
| **SEC-009** | Unrestricted Tool Scope | MEDIUM | Wildcard permissions (`*`, `Bash(*)`, `Write(*)`) declared in `allowed-tools` frontmatter. |
| **SEC-010** | Deceptive Installer Pattern | HIGH | Scripts masquerading as standard installers while downloading unverified secondary payloads in the background. |
| **SEC-011** | Executable in Assets | HIGH | Executable binaries (`.exe`, `.bin`, `.so`, `.dylib`) concealed inside static documentation or image asset folders. |
| **SEC-012** | Allowed-Tools Scope Violation | HIGH | Shell commands or execution scripts in skill body when frontmatter `allowed-tools` excludes shell execution. |

---

## Quality Rules Matrix (QUAL-001 to QUAL-009)

| Rule ID | Name | Severity | Purpose |
| :--- | :--- | :--- | :--- |
| **QUAL-001** | Trigger Clarity | MEDIUM | Ensures frontmatter `description` contains concrete activation conditions (e.g., "Use when..."). |
| **QUAL-002** | Directory Alignment | LOW | Verifies that the enclosing folder name matches the frontmatter `name`. |
| **QUAL-003** | Progressive Disclosure Budget | MEDIUM | Flags `SKILL.md` bodies exceeding 500 lines or ~5,000 tokens, enforcing extraction of secondary manuals into `references/`. |
| **QUAL-004** | Broken Disclosure Pointers | HIGH | Checks that all cited files in `references/...` and `scripts/...` exist on disk. |
| **QUAL-005** | Description Bloat | LOW | Flags startup descriptions exceeding 150 words to prevent excessive always-loaded prompt burn. |
| **QUAL-006** | Applicability Hijacking | HIGH | Detects overbroad trigger descriptions that claim all tasks (e.g., "Use for all coding tasks" or "Always invoke"). |
| **QUAL-007** | Version Semantics | LOW | Validates that the declared version string conforms to Semantic Versioning (SemVer 2.0). |
| **QUAL-008** | Missing Examples | LOW | Encourages inclusion of concrete user prompt and tool invocation examples. |
| **QUAL-009** | Nested Reference Verification | MEDIUM | Enforces that secondary files inside `references/` do not contain recursive, broken pointers. |

---

## Context Linter Rules (CTX-001 to CTX-004)

The context linter (`skillforge lint-context`) scans root-level instruction documents such as `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.windsurfrules`, and `.gemini/GEMINI.md`:

| Rule ID | Name | Severity | Description |
| :--- | :--- | :--- | :--- |
| **CTX-001** | File Line Ceiling | HIGH | Context file exceeds 150 lines, degrading model attention and inflating per-turn token spend. |
| **CTX-002** | Contradictory Constraints | MEDIUM | Identifies contradictory negative constraints (e.g., "never do X" alongside "always do X"). |
| **CTX-003** | Buzzword & Filler Hygiene | LOW | Flags empty buzzwords (e.g., "seamless", "tapestry", "game changer") that waste tokens without providing operational value. |
| **CTX-004** | Duplicated Rules | LOW | Detects identical rules repeated across multiple context documents. |

---

## Static Scanner Scope & Honest Limits

SkillForge provides deterministic static analysis. To set clear expectations:

- **What SkillForge Catches:** Deterministic threats such as shell injection pipelines, reverse shells, credential path traversal, hardcoded tokens, Python AST taint flows from environment variables to network calls, and prompt bloat.
- **What Requires Human Confirmation & OS Sandboxes:** Pure natural language policy evasion (instructions that coax models into non-compliant actions without using recognizable jailbreak keywords or executable shell scripts) cannot be reliably detected by regex or AST analysis alone.
- **Recommended Defense-in-Depth:** Combine SkillForge static auditing with containerized or OS-level sandboxing, and mandate human approval for irreversible external actions.
