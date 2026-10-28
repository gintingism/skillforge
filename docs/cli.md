# CLI Reference

SkillForge provides a CLI powered by Typer. Run `skillforge --help` to see all commands.

## Commands

### `skillforge add <spec>`
Fetch, security-audit, and install a skill directly from a GitHub repository into your active project, recording its SHA-256 digest in `skillforge.lock`:
```bash
skillforge add anthropics/skills:pdf
skillforge add gintingism/skillforge:systematic-debugging
```
Options:
- `-p, --project PATH`: Target project root (defaults to `.`).
- `-g, --global`: Install into user-level assistant configs.
- `--skip-audit`: Skip security auditing before installation.

### `skillforge sync`
Deterministically install and verify all skills pinned in `skillforge.lock` (verifying SHA-256 integrity and security audit rules before installing):
```bash
skillforge sync
skillforge sync --project ./my-repo
```

### `skillforge doctor`
Run a full health, security, and context budget diagnostic across installed skills:
```bash
skillforge doctor
skillforge doctor --global
skillforge doctor --json
```

### `skillforge diff <target_a> [target_b]`
Compare changes between a local skill and an upstream repo, or between two skill directories:
```bash
skillforge diff ./skills/my-skill
skillforge diff my-skill gintingism/skillforge:my-skill
```

### `skillforge budget`
Profile context window token usage across installed or built-in skills, separating always-loaded startup pointer tokens from on-demand `SKILL.md` body and disclosed resource tokens:
```bash
skillforge budget
skillforge budget --builtin
skillforge budget --json
```

### `skillforge audit <path>`
Scan a skill file or directory for prompt injections, zero-width unicode, dangerous shell commands, broken `references/` or `scripts/` pointers, and progressive disclosure token limits:
```bash
skillforge audit ./skills/my-skill
skillforge audit ./skills/my-skill --strict
skillforge audit ./skills/my-skill --json
```

### `skillforge list`
List all installed skills across detected assistants:
```bash
skillforge list
skillforge list --global
```

### `skillforge remove <name>`
Remove an installed skill from all detected assistants and update `skillforge.lock`:
```bash
skillforge remove my-skill
```

### `skillforge create <name>`
Create a new skill file or modular directory structure:
```bash
skillforge create code-review -d "Review code carefully. Use when auditing PRs."
skillforge create full-tool -d "Complete tool. Use when automating workflows." --full
```

### `skillforge validate <path>`
Validate a `SKILL.md` file against schema standards:
```bash
skillforge validate ./skills/my-skill/SKILL.md
skillforge validate ./skills/my-skill/SKILL.md --json
```

### `skillforge pack <path>` / `skillforge unpack <archive>`
Package a skill directory into a zip file or safely unpack one:
```bash
skillforge pack ./skills/my-skill --output ./my-skill.zip
skillforge unpack ./my-skill.zip --output ./skills
```

### `skillforge search <query>`
Search for skills across local and built-in registries:
```bash
skillforge search debugging
```

### `skillforge install <name>`
Install a local or built-in skill into detected assistant targets:
```bash
skillforge install systematic-debugging
skillforge install systematic-debugging --global
```
