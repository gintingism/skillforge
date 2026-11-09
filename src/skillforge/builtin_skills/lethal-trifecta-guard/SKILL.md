---
name: lethal-trifecta-guard
description: Enforce isolation boundaries against the Lethal Trifecta (OWASP AST10) by separating private credential access, untrusted external content ingestion, and outbound network egress. Use when designing tool permissions, auditing multi-step agent workflows, or handling untrusted web and webhook inputs.
license: MIT
allowed-tools: Read Grep Glob Bash
metadata:
  version: "1.0"
  category: "security"
---

# Lethal Trifecta Guard

An agent workflow becomes vulnerable to silent data exfiltration when a single execution context combines three capabilities simultaneously (the **Lethal Trifecta**, OWASP Agentic Skills Top 10):

1. **Private Data Access**: Reading environment secrets, `.env` files, database records, or local credentials.
2. **Untrusted Content Ingestion**: Fetching arbitrary external URLs, third-party issues, pull request comments, or user-submitted documents.
3. **External Network Egress**: Performing outbound HTTP requests, webhook calls, or dynamic DNS/markdown image rendering.

When all three legs coexist in one turn or skill, an indirect prompt injection inside leg (2) can instruct the agent to read leg (1) and transmit it through leg (3).

## Mandatory Isolation Rules

1. **Break At Least One Leg Per Execution Context**
   - Never grant a single skill or subagent simultaneous access to private credentials, untrusted external text, and outbound network egress.
   - Consult `references/isolation-boundaries.md` for architecture patterns that split ingestion, processing, and egress across isolated stages.

2. **Two-Stage Ingestion Pipeline**
   - **Stage A (Untrusted Parser)**: Fetch and parse external content in a restricted context with no access to secrets (`env -i` or network-only read scope) and emit a strict, schema-validated JSON artifact.
   - **Stage B (Privileged Executor)**: Read only the validated structural fields (such as numeric IDs or enum values) from Stage A without passing raw untrusted prose into a privileged context.

3. **Egress Allowlisting**
   - Restrict outbound HTTP calls to fixed, pre-declared API hosts.
   - Reject dynamic URL construction where query parameters or request bodies interpolate raw environment variables or file contents.

4. **Pre-Flight Audit Verification**
   - Run `skillforge audit --strict` (and `--sandbox` when Python helper scripts are present) on every skill package before syncing to agent directories:

```bash
skillforge audit ./skills --strict --sandbox
```
