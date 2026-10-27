---
name: security-threat-modeler
description: Map trust boundaries, attack surfaces, object-level authorization (IDOR/BOLA), SSRF vectors, and injection sinks before shipping backend or agent endpoints. Use when reviewing security, designing APIs, or auditing auth flows.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Security Threat Modeler Protocol

Perform structured trust-boundary and attack-surface analysis before merging authentication, API, webhook, file-handling, or tool-execution changes.

## 1. Enumerate Trust Boundaries

1. **Identify Untrusted Inputs**:
   - List every external entry point: HTTP params, headers, webhook bodies, uploaded archives, database records containing user text, and LLM/tool outputs.
2. **Trace Principal & Tenant Scope**:
   - Verify how the caller's identity (`user_id`, `org_id`, `role`) is bound to the session token rather than read from request parameters.

## 2. High-Severity Vulnerability Checklist

- **Broken Object Level Authorization (IDOR / BOLA)**:
  - Scope every read, update, and delete query by both resource ID and authenticated tenant/owner (`WHERE id = :id AND org_id = :auth_org_id`).
- **Server-Side Request Forgery (SSRF)**:
  - Reject user-supplied URLs targeting loopback (`127.0.0.0/8`, `::1`), link-local metadata (`169.254.169.254`), and RFC1918 private ranges; validate resolved IP addresses immediately before connecting.
- **Path Traversal & Archive Extraction**:
  - Resolve candidate paths with `Path.resolve()` and assert `target.is_relative_to(base_dir)` before reading, writing, or extracting zip/tar members.
- **Command & Query Injection**:
  - Execute subprocesses as argument arrays with `shell=False` and bind all SQL parameters via parameterized queries.
- **Webhook & Callback Authenticity**:
  - Verify HMAC signatures using constant-time comparison (`hmac.compare_digest`) over the raw request body and enforce timestamp replay windows.

## 3. Completion Gate

- Write at least one negative security test proving an unauthorized tenant, traversed path, or forged signature is rejected with an explicit error status.
