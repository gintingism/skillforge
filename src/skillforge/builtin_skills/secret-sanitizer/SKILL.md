---
name: secret-sanitizer
description: Audit staged files, commit diffs, and terminal outputs for leaked API keys, tokens, and private credentials. Use when preparing git commits, staging code changes, or configuring environment variables.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Secret Sanitizer Protocol

Block credentials, private keys, session tokens, and environment secrets from leaking into version control, commit logs, or terminal session histories.

## 1. High-Entropy Credential Patterns

Scan git diffs and staged changes for high-entropy tokens and signature prefixes before running `git commit`:

| Secret Type | Signature Pattern | Example Prefix |
| :--- | :--- | :--- |
| **GitHub Tokens** | `ghp_[A-Za-z0-9]{36}`, `github_pat_[A-Za-z0-9_]{82}` | `ghp_`, `github_pat_` |
| **Anthropic API Keys** | `sk-ant-[A-Za-z0-9_-]{32,}` | `sk-ant-` |
| **OpenAI API Keys** | `sk-[A-Za-z0-9]{48}` | `sk-` |
| **Google Cloud / Gemini** | `AIzaSy[A-Za-z0-9_-]{33}` | `AIzaSy` |
| **AWS Credentials** | `AKIA[0-9A-Z]{16}` | `AKIA` |
| **Private Keys** | `-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----` | `-----BEGIN` |

## 2. Pre-Commit Staging Audit Procedure

1. **Review Diff of Staged Files**:
   `git diff --cached --unified=0`
2. **Verify `.gitignore` Coverage**:
   Ensure `.env`, `.env.local`, `.env.*.local`, `*.pem`, `*.key`, `*.pfx`, and credentials caches (`.aws/`, `.gcloud/`) are explicitly ignored.
3. **Check Staged File List**:
   `git diff --cached --name-only`
   Reject any file matching `.env*`, `credentials.json`, `id_rsa`, or service account keys.

## 3. Redaction & Remediation Rule

- If a secret was committed locally:
  Do not push. Reset the commit (`git reset HEAD~1`), sanitize the code to read from `os.environ` or a secrets manager, and rotate the compromised credential immediately.
- Test suites must use dummy mock values (e.g., `"test-api-key"`, `"dummy-token-123"`) rather than live keys.
