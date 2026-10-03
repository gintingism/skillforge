---
name: agent-observability
description: Make agent work auditable through explicit outcomes, errors, tests, and bounded progress records.
---

# Agent observability

This skill defines reporting behavior. It does not add telemetry or external tracking.

Record:

- requested scope;
- actions that changed files or state;
- commands run and results;
- errors with exact short messages;
- remaining blockers;
- final file and commit references when relevant.

Never log secrets, credentials, tokens, or unnecessary personal data. Prefer local test evidence over vague success claims.
