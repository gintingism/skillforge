# Troubleshooting and FAQ

Common questions, operational recipes, and troubleshooting steps for SkillForge.

---

## Frequently Asked Questions

### 1. What if my skill contains legitimate security examples that trigger SEC-002?
SkillForge's prompt injection auditor (`SEC-002`) inspects sentence grammar and markdown quoting:
- If a suspicious phrase (e.g., `"ignore previous instructions"`) appears inside markdown quotation blocks (`> ...`) or backticks as a defense example, SkillForge downgrades the finding to `MEDIUM`.
- Direct imperative directives remain scored as `CRITICAL`.
- If you need to allow a specific finding in a specialized security skill, pass `--allow-finding SEC-002` during audit, or place `# skillforge: ignore SEC-002` above the snippet.

### 2. How do I fix lockfile mismatch errors (`skillforge verify`)?
If you intentionally modified a skill on disk and `skillforge verify` fails with a hash mismatch:
```bash
# Re-add or update the skill to recompute SHA-256 and update skillforge.lock
skillforge add ./skills/my-skill
```
Never manually edit the SHA-256 strings in `skillforge.lock`.

### 3. Why does SkillForge flag skills exceeding 500 lines (`QUAL-003`)?
Modern AI coding models exhibit attention degradation when prompts become excessively long. Injecting an unconstrained 1,500-line markdown manual directly into the context window wastes tokens and increases hallucination rates.

To resolve `QUAL-003`:
1. Keep the core trigger description, overview, and primary step-by-step workflow in `SKILL.md` (under 500 lines).
2. Move extensive checklists, schema definitions, and deep background material into the `references/` folder.
3. Or run `skillforge optimize ./skills/my-skill` to perform this extraction automatically.

### 4. How do I configure GitHub Code Scanning to display SkillForge findings?
SkillForge natively exports to the OASIS SARIF v2.1.0 standard. In your GitHub Actions workflow:

```yaml
- name: Run SkillForge Audit
  run: |
    pip install agent-skillforge
    skillforge audit ./skills --sarif results.sarif

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

Findings will appear directly in the **Security > Code scanning** tab of your GitHub repository.

### 5. Why are my skills installed to `.gemini/` instead of `.cursor/`?
SkillForge inspects your workspace for platform signature directories:
- If `.gemini/` is present, it targets Google Antigravity.
- If `.cursor/` is present, it targets Cursor.
- If multiple assistants are installed in your workspace, SkillForge automatically installs skills into all detected targets.
- You can force a specific target assistant using the `--target` flag:
  ```bash
  skillforge install systematic-debugging --target cursor
  ```

---

## Troubleshooting Error Codes

| Exit Code | Cause | Resolution |
| :--- | :--- | :--- |
| **0** | Clean run | All checks passed with zero blocking issues. |
| **1** | Security audit failure | `CRITICAL` or `HIGH` findings detected in scanned skills. Run `skillforge audit <path>` to inspect details. |
| **2** | Quality / Context failure | Ran with `--strict` and encountered `MEDIUM` quality violations or broken reference pointers. |
| **3** | Integrity mismatch | Files in managed skills differ from the hashes recorded in `skillforge.lock`. |
