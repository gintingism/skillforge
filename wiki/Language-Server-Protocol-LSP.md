# Language Server Protocol (LSP) Daemon

SkillForge includes an implementation of the Language Server Protocol (LSP 3.17) over standard I/O. It provides real-time linting, security checking, and schema completions directly inside Cursor, VS Code, Neovim, and other LSP-compatible editors.

---

## Why an LSP for Agent Skills?

Authoring agent skills in markdown often introduces silent errors:

* Unclosed or malformed YAML frontmatter that crashes agent discovery parsers.
* Missing recommended or required fields (`name`, `description`).
* Overly large documents that exceed token budgets and degrade context quality.
* Accidental introduction of dangerous shell commands or sensitive secrets.
* Broken relative markdown links pointing to non-existent reference guides.

With `skillforge lsp`, errors are reported as you type, before runtime or deployment.

---

## Features

### 1. Real-Time Diagnostics

The LSP daemon inspects your document on open, change, and save, emitting standard diagnostic messages:

| Rule Code | Severity | Description |
| :--- | :--- | :--- |
| `FMT-001` | Error | Missing opening YAML frontmatter delimiter (`---`). |
| `FMT-002` | Error | Unclosed YAML frontmatter. |
| `FMT-003` | Error | Frontmatter is not a key-value dictionary. |
| `FMT-004` | Error | Required field `name` is missing or empty. |
| `FMT-005` | Warning | Skill name should be lowercase kebab-case (e.g., `git-commit-helper`). |
| `FMT-006` | Warning | Missing recommended field `description`. |
| `FMT-007` | Error | YAML syntax parsing failure. |
| `TOK-001` | Warning | Content exceeds 5,000 tokens (recommends splitting into `references/`). |
| `SEC-001` | Error | Destructive commands detected (`rm -rf /` or wildcard deletion). |
| `SEC-002` | Error | Remote pipeline execution (`curl ... | bash`). |
| `SEC-003` | Error | Direct modification of system network configuration (`/etc/hosts`). |
| `SEC-004` | Warning | Common prompt injection patterns detected. |
| `SEC-005` | Warning | Plaintext API tokens or private keys found in document. |
| `SEC-013` | Error | Memory poisoning targeting `AGENTS.md` or `CLAUDE.md`. |
| `SEC-015` | Error | Obfuscated base64 execution or hex payload detected. |
| `SEC-016` | Error | Destructive resource exhaustion patterns (fork bombs). |
| `REF-001` | Warning | Relative markdown link references a non-existent file. |

### 2. Live Hover Analysis

Hovering over a `SKILL.md` document displays metadata:

* Total line, word, and token counts.
* Estimated context window weight.
* Active warning and error counts.
* Live security score calculation (out of 100).

### 3. Autocompletion

Typing in the frontmatter header triggers suggestions for standard skill fields:

* `name`
* `description`
* `version`
* `author`
* `tags`
* `allowed-tools`

---

## Editor Configuration

### Running the Daemon

Start the server over standard input and output:

```bash
skillforge lsp
```

### Cursor and VS Code Setup

To configure the server in VS Code or Cursor using a generic LSP extension (such as the Generic LSP Client extension or custom task configuration):

```json
{
  "lsp.servers": {
    "skillforge": {
      "command": "skillforge",
      "args": ["lsp"],
      "filetypes": ["markdown"],
      "rootMarkers": [".git", "SKILL.md", "pyproject.toml"]
    }
  }
}
```

### Neovim Setup (`nvim-lspconfig`)

In your Neovim Lua configuration:

```lua
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

if not configs.skillforge then
  configs.skillforge = {
    default_config = {
      cmd = { 'skillforge', 'lsp' },
      filetypes = { 'markdown' },
      root_dir = lspconfig.util.root_pattern('SKILL.md', '.git'),
      settings = {},
    },
  }
end

lspconfig.skillforge.setup({})
```
