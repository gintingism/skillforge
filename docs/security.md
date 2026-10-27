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
| **`SEC-004`** | **MEDIUM** | Credential Harvesting | Detects unprompted direct reads to sensitive user paths (`~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.config/gcloud`). |
| **`QUAL-001`** | **LOW** | Trigger Quality | Verifies whether the skill description includes explicit activation triggers (`when`, `use when`, `for`) necessary for token-efficient progressive disclosure. |
| **`QUAL-002`** | **MEDIUM** | Spec Compliance | Ensures directory name matches the `name` field in YAML frontmatter and validates identifier safety. |

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
