# Lethal Trifecta Isolation Boundaries

## Capability Matrix

| Workflow Stage | Private Data / Secrets | Untrusted External Input | Outbound Network Egress | Risk Status |
| :--- | :--- | :--- | :--- | :--- |
| **Static Code Analyzer** | Yes (repo code) | No | No | Safe (1 of 3) |
| **Sandboxed Web Scraper** | No (`env -i`) | Yes (remote HTML/JSON) | Yes (read-only fetch) | Safe (2 of 3, no secrets) |
| **Deployment Notifier** | Yes (webhook token) | No (structured build status) | Yes (fixed Slack/GitHub API) | Safe (2 of 3, no untrusted input) |
| **Unrestricted Triage Bot** | Yes (`.env` / tokens) | Yes (public issue body) | Yes (arbitrary HTTP POST) | **CRITICAL (`SEC-014`)** |

## Remediation Patterns

1. **Strip Environment Variables Before Running Untrusted Parsers**
   - Invoke external document parsers with a minimal environment (`PATH`, `PYTHONUTF8=1`) so that even if parser logic is compromised, no API keys exist in process memory.
2. **Replace Free-Form Summaries with Typed Enums**
   - When triaging untrusted bug reports or PRs, classify into fixed categories (`bug`, `docs`, `security`) rather than forwarding raw user strings into downstream shell or HTTP calls.
3. **Require Explicit Human Confirmation for Egress**
   - Any action that sends local repository data to an external domain must pause and display the exact destination host and payload diff for operator approval.
