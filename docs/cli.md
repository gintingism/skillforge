# CLI

SkillForge uses Typer. Run `skillforge --help` for command discovery.

## Create and validate

```powershell
skillforge create code-review --description "Review code carefully" --directory .\skills\code-review
skillforge validate .\skills\code-review\SKILL.md
skillforge validate .\skills\code-review\SKILL.md --json
```

Names must be safe filesystem path segments: lowercase letters, numbers, `-`, and `_`.
Use `--json` for automation. Success emits `valid`, `path`, `name`, and `description`; failure emits `valid`, `path`, and `error`. Human-readable output and exit codes stay unchanged.

## Local registry

Local registry layout:

```text
.skillforge/
└── code-review/
    └── SKILL.md
```

```powershell
skillforge search review --registry .\.skillforge
skillforge install code-review --registry .\.skillforge --project .
```

Built-in skills ship with SkillForge. Local registry entries override built-ins with the same name. Search and install use both sources explicitly.

## Package

```powershell
skillforge pack .\skills\code-review --output .\code-review.zip
```
