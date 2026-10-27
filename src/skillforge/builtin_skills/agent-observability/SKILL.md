---
name: agent-observability
description: Instrument agent tool calls, prompt latency, token expenditure, and error boundaries with structured OpenTelemetry or JSON-L logging. Use when debugging agent loops or optimizing multi-agent tracing.
license: MIT
compatibility: Python 3.10+, Node.js 18+
metadata:
  version: "1.1.0"
  author: "SkillForge Team"
---

# Agent Observability & Telemetry

Instrument agent operations with structured telemetry to measure token efficiency, latency bottlenecks, and error propagation across tool executions.

## Execution Standards

1. **Structured Tracing**:
   - Every agent invocation must carry a trace correlation ID (`trace_id`, `step_index`, `parent_span_id`).
   - Log tool calls as discrete spans with input parameters, execution duration, and exit status.
2. **Error Isolation**:
   - Distinguish cleanly between model inference errors, tool schema validation errors, and subprocess execution failures.
   - Format execution failures with exact stderr output and return codes.
3. **Telemetry Sanitization**:
   - Redact API keys, session tokens, and personal credentials before emitting spans to telemetry backends.
   - Truncate payload bodies exceeding 16KB into structured head/tail snippets with byte offsets.
