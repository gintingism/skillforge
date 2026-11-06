# Security Auditor

SkillForge includes an integrated security auditor and static analysis engine (`skillforge audit`) designed specifically for AI agent skills and instruction files.

## The Threat Vector: Skill Supply-Chain Attacks

Unlike regular text files, `SKILL.md` documents are **instruction sources**. When an autonomous coding assistant loads a third-party skill, it follows the procedural steps and may execute companion scripts in its sandboxed or local terminal.

Common attack vectors in community-shared skills include:
- **Hidden Zero-Width Payloads:** Invisible unicode codepoints embedded between words that are invisible in GitHub code review but parsed by LLMs as execution instructions.
- **Indirect Prompt Injection:** Directives instructing the model to ignore user constraints, disable safety boundaries, or leak previous conversation turns.
- **Script Exfiltration (SkillJect):** Benign-looking documentation that points to a helper script in `scripts/` containing unauthorized `curl`, `wget`, or credential-harvesting commands.

---

## Audit Rule Reference

| Rule ID | Severity | Focus Area | Description |
| :--- | :--- | :--- | :--- |
| **`SEC-001`** | **CRITICAL** | Hidden Unicode | Detects zero-width spaces (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`), bidirectional overrides, and unicode tags used to conceal prompt instructions. |
| **`SEC-002`** | **CRITICAL** | Prompt Injection | Scans for jailbreak patterns (`ignore previous instructions`, `system override`, `developer mode`, `DAN mode`). |
| **`SEC-003`** | **HIGH** | Dangerous Shell | Identifies risky execution patterns in scripts and markdown blocks (`curl \| bash`, base64 piping to shell, outbound data exfiltration via POST). |
| **`SEC-004`** | **MEDIUM** | Credential Harvesting | Detects unprompted direct reads to sensitive user paths (SSH private keys, AWS credentials, gcloud configs). |
| **`SEC-005`** | **HIGH** | Exfiltration Endpoints | Detects outbound data transmission to webhook or request-capture domains (`webhook.site`, `pipedream.net`, `requestbin.net`). |
| **`SEC-006`** | **CRITICAL / HIGH** | Hardcoded Secrets | Detects hardcoded API keys and provider tokens (`ghp_`, `github_pat_`, `sk-ant-`, `AIzaSy`, `AKIA`). |
| **`SEC-007`** | **HIGH** | Markdown Link Spoofing | Detects deceptive links where the visible URL host differs from the target destination host. |
| **`SEC-008`** | **CRITICAL / HIGH** | Python AST & Taint Analysis | Inspects bundled `.py` scripts via Python AST for `eval()`, `exec()`, `subprocess(..., shell=True)`, unsafe deserialization, and environment-to-network taint flows. |
| **`SEC-009`** | **MEDIUM** | Unrestricted Tool Scope | Flags wildcard tool permissions (`*`, `Bash(*)`) in `allowed-tools` YAML frontmatter. |
| **`SEC-010`** | **HIGH** | Deceptive Installer Pattern | Flags prose instructions guiding users or agents to execute piped shell installers (`curl ... \| bash`, `irm ... \| iex`). |
| **`SEC-011`** | **HIGH / MEDIUM** | Executable Payload in Assets | Flags native executables (ELF, Mach-O, PE headers) as HIGH and script or binary file types (`.sh`, `.ps1`, `.bat`, `.exe`, `.dll`, `.so`, `.jar`, ...) under `assets/` as MEDIUM. Runnable code belongs in `scripts/`, where it gets audited as code. Text assets are also scanned for prompt injection and hidden unicode. |
| **`QUAL-001`** | **LOW** | Trigger Quality | Verifies whether the skill description includes explicit activation triggers (`when`, `use when`, `for`) necessary for token-efficient progressive disclosure. |
| **`QUAL-002`** | **MEDIUM** | Spec Compliance | Ensures directory name matches the `name` field in YAML frontmatter and validates identifier safety. |
| **`QUAL-003`** | **LOW** | Context Budget Limit | Flags `SKILL.md` bodies exceeding 500 lines or ~5,000 tokens so reference docs are extracted into `references/`. |
| **`QUAL-004`** | **HIGH** | Broken Resource Pointer | Verifies that every `references/...`, `scripts/...`, or `assets/...` path cited in `SKILL.md` exists in the package. |
| **`QUAL-006`** | **MEDIUM** | Applicability Hijacking | Flags overbroad trigger descriptions that attempt to force activation on every user prompt. |
| **`QUAL-008`** | **LOW** | Metadata Value Types | The agentskills.io spec maps string keys to string values in `metadata`. Flags numbers and booleans such as `version: 1.0`; quote them (`version: "1.0"`). |
| **`QUAL-007`** | **LOW** | agentskills.io Name Format | Validates strict naming compliance (`^[a-z0-9]+(-[a-z0-9]+)*$`) for portability across all runtimes. |
| **`QUAL-009`** | **LOW** | Nested Reference Chain | Flags reference files that link to secondary `references/...` files instead of keeping progressive disclosure one-level-deep from `SKILL.md`. |

---

## CLI Usage

### Basic Audit
```bash
skillforge audit ./skills/my-skill
```

### Strict Mode for CI/CD
Fail the command with exit code `1` if any warning or low-severity finding is detected:
```bash
skillforge audit ./skills/my-skill --strict
```

### Machine-Readable JSON
Emit structured audit reports for integration into pre-commit hooks or automated review bots:
```bash
skillforge audit ./skills/my-skill --json
```

Example JSON Output:
```json
{
  "target": "my-skill",
  "passed": true,
  "score": 100,
  "findings_count": 0,
  "findings": []
}
```

---

## Regression Corpus

[`tests/test_corpus.py`](https://github.com/gintingism/skillforge/blob/main/tests/test_corpus.py) holds known-malicious and known-benign skill snippets. Each malicious case names the rule that must fire, and benign cases must produce no CRITICAL or HIGH finding. The corpus is small and hand-written, so it guards against regressions in the existing patterns; it does not measure real-world detection rates. Add a case whenever you fix a missed detection or a false positive.

## Honest Static Scanner Scope & Limitations

Static analysis is an essential first line of defense for agent skill packages, but it has defined boundaries:

1. **What Static Analysis Guarantees:**
   - Deterministic discovery of malicious shell pipelines, reverse shells, and untrusted network endpoints.
   - AST taint tracking in bundled Python scripts to prevent environment variable leaks and code injection.
   - Zero-width unicode sanitization and prompt injection pattern detection.
   - Resource pointer integrity and identifier formatting verification.

2. **What Requires Human-in-the-Loop & Runtime Sandboxing:**
   - **Semantic Policy Evasion:** Subtly biased or evasive natural language instructions that do not contain explicit injection phrases or code execution payloads cannot be definitively categorized by pattern matching alone.
   - **Dynamic Server Payloads:** If a skill instructs an agent to call an external API that later changes its payload response, static analysis cannot inspect runtime remote data.
   - **Complementary Defenses:** We recommend pairing SkillForge static audits with runtime container sandboxing (e.g. gVisor, Docker, or Windows sandbox environments) and requiring explicit user approval for destructive commands.

