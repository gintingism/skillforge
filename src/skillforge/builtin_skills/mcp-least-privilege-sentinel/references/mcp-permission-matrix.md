# MCP Permission Matrix and Blast Radius Boundaries

## Tool Classification Matrix

| Tool Category | Example Verbs | Blast Radius | Approval Requirement | Required Constraints |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Read-Only** | `get_*`, `list_*`, `search_*`, `read_*` | Low | Automatic execution permitted | Scoped directory filter, strict pagination limits |
| **Tier 2: Reversible Mutation** | `create_draft`, `stage_file`, `format_code` | Medium | Notify operator with diff | Atomic rollbacks, isolated worktree target |
| **Tier 3: Destructive Action** | `delete_*`, `drop_*`, `deploy_*`, `exec_*` | Critical | Explicit operator approval required | Two-phase confirmation, audit logging to stderr |

## Hardening Checklist for MCP Servers

1. **Pin Server Package Versions**
   - In `mcp.json`, always specify exact package versions (for example `@modelcontextprotocol/server-postgres@0.6.2`) rather than unpinned tags to prevent upstream supply-chain tampering.

2. **Environment Variable Substitution**
   - Never commit plaintext API keys into the `env` block of `mcp.json`. Use environment variable expansion (`${DATABASE_URL}`) evaluated by the client runtime.

3. **Stderr vs Stdout Separation**
   - Send JSON-RPC protocol payloads strictly to `stdout`. Direct all diagnostic logs, warning traces, and error outputs to `stderr` to prevent protocol stream corruption.
