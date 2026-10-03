# CLI

SkillForge uses Typer. Run `skillforge --help` for command discovery.

## Create and validate

```powershell
skillforge create code-review --description "Review code carefully" --directory .\skills\code-review
skillforge validate .\skills\code-review\SKILL.md
```

Names must be safe filesystem path segments: lowercase letters, numbers, `-`, and `_`.

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
