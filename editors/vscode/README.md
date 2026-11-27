# SkillForge IDE Extension (VS Code / Cursor / Open VSX)

Thin Language Server Protocol (LSP) client wrapping `skillforge lsp` over stdio.

## Features

- Live diagnostics on `SKILL.md` files (security score, prompt injection, AAIF 6-field frontmatter checks).
- Inline CodeLens showing the current security score plus Pointer and Body token counts.
- Quick-Fix CodeAction to normalize non-portable frontmatter into the 6-field AAIF standard.
- Hover documentation and frontmatter key autocompletion.
- Commands: `SkillForge: Audit Active SKILL.md` and `SkillForge: Normalize SKILL.md to AAIF 6-Field Standard`.

## Prerequisites

Install the SkillForge CLI in your active environment:

```bash
pip install agent-skillforge
```

If `skillforge` is not on your `PATH`, set `skillforge.executablePath` in VS Code or Cursor settings.

## Packaging Locally

```bash
cd editors/vscode
npm install
npx @vscode/vsce package
code --install-extension skillforge-vscode-0.11.0.vsix
```
