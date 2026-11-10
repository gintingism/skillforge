---
name: mcp-least-privilege-sentinel
description: Enforce least-privilege boundaries and read-write segregation for Model Context Protocol (MCP) server tools. Use when designing MCP tools, configuring mcp.json permissions, or auditing agent tool blast radius.
license: MIT
allowed-tools: Read Grep Glob Bash
metadata:
  version: "1.0"
  category: "security"
---

# MCP Least Privilege Sentinel

Model Context Protocol (MCP) servers grant autonomous coding agents programmatic access to local filesystems, databases, API gateways, and system runtimes. Without granular permission boundaries, an agent executing an untrusted tool call can accidentally mutate critical infrastructure or leak host secrets.

## Core Governance Rules

1. **Read-Write Tool Segregation**
   - Never combine read-only queries with mutation or deletion operations in a single MCP tool definition.
   - Separate tools into distinct verbs: use `get_user` or `list_records` for read operations, and isolate mutating operations into `update_user` or `archive_records`.
   - Consult `references/mcp-permission-matrix.md` for tool classification guidelines and permission tier assignments.

2. **Strict Filesystem Boundaries**
   - Never mount entire disk roots (`/`, `C:\`, `~`, `$HOME`) in MCP server arguments.
   - Explicitly scope server directory access to the active workspace or designated sandbox output folder:

```bash
# Insecure:
npx -y @modelcontextprotocol/server-filesystem /

# Secure:
npx -y @modelcontextprotocol/server-filesystem@0.6.2 ./workspace
```

3. **Input Schema Validation and Enum Constraints**
   - Enforce strict JSON Schema types on every MCP tool parameter.
   - Reject untrusted string interpolation into shell commands or database queries.
   - Use discrete enums for modes or options rather than open-ended string flags.

4. **Audit MCP Configuration Files**
   - Run `skillforge audit-mcp` to verify that `mcp.json` or `claude_desktop_config.json` does not expose plaintext secrets or unpinned runtime binaries:

```bash
skillforge audit-mcp ./mcp.json --strict
```
