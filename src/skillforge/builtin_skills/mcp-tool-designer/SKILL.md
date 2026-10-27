---
name: mcp-tool-designer
description: Architect high-performance, type-safe Model Context Protocol (MCP) servers and tools with strict JSON schemas, token bounds, idempotent annotations, and decoupled error reporting. Use when designing MCP tools or building AI agent integrations.
license: MIT
compatibility: Python 3.10+, TypeScript 5+
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# MCP Tool Designer Protocol

Design robust, idiomatic Model Context Protocol (MCP) tools that minimize token waste and provide deterministic execution for AI agents.

## Core Design Principles

1. **Explicit Schema Typing**:
   - Define exact parameter types, enums, defaults, and bounds (`minimum`, `maximum`, `max_length`).
   - Write clear parameter docstrings explaining constraints and expected formats.
2. **Tool Annotations & Hints**:
   - Always declare `read_only_hint` (True for queries/inspections; False for state mutations).
   - Declare `idempotent_hint` (True if repeating the call with identical inputs produces the identical state).
3. **Payload & Character Bounds**:
   - Enforce hard response limits (e.g. 25,000 characters or 100 items per call).
   - Provide pagination (`cursor`, `offset`, `limit`) instead of unbounded list returns.
4. **Clean Error Separation**:
   - Protocol messages (JSON-RPC) use stdout; diagnostic and debug logs must strictly write to stderr.
   - Return structured error dictionaries (`{"error": "message", "code": 404}`) rather than throwing unhandled exceptions that crash the stdio stream.
