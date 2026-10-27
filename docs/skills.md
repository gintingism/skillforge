# Built-in Skills Catalog

SkillForge ships with 16 production-grade, zero-slop skills. These skills directly counter known failure patterns observed in repository-level agent evaluations (SWE-bench).

---

## 1. Code Quality & Architectural Discipline

### `blast-radius-containment`
- **Purpose:** Analyze upstream callers and enforce strict minimal-diff boundaries before modifying shared code or public APIs.
- **Trigger:** Use when modifying core utilities, database models, public API signatures, or widely imported types.
- **Key Invariants:** Rule of Least Mutation, upstream call-graph audit, maximum 3-file touch budget.

### `antislop-code`
- **Purpose:** Enforce comment hygiene, eliminate generic AI-generated narrative filler, and stop speculative over-engineering.
- **Trigger:** Use when reviewing code, refactoring modules, or auditing pull requests.
- **Key Invariants:** Deletes trivial echo comments, preserves domain invariants, blocks premature abstractions (YAGNI).

### `spec-driven-development`
- **Purpose:** Design systems contract-first using typed schemas, OpenAPI/JSON-Schema models, and failing test harnesses before writing application logic.
- **Trigger:** Use when architecting new modules, APIs, or data models.
- **Key Invariants:** Red-green verification loop, typed boundary definitions.

### `zero-downtime-migration`
- **Purpose:** Plan and execute non-breaking database schema changes and API payload evolutions using the Expand-Contract pattern.
- **Trigger:** Use when modifying SQL tables, ORM models, or public API endpoints in production systems.
- **Key Invariants:** Four phases (Expand dual-write → Async batch backfill → Switch reads → Contract cleanup). No in-place column renames.

---

## 2. Autonomous Loop Stability & Debugging

### `systematic-debugging`
- **Purpose:** Execute a disciplined four-phase root-cause investigation loop before modifying code.
- **Trigger:** Use when diagnosing failing tests, runtime crashes, race conditions, or performance regressions.
- **Key Invariants:** Phase 1 Reproduce → Phase 2 Isolate → Phase 3 Falsifiable Hypotheses → Phase 4 Surgical Patch.

### `cognitive-loop-breaker`
- **Purpose:** Detect and interrupt trial-and-error death spirals where repetitive edits fail tests across consecutive turns.
- **Trigger:** Use when stuck in recurring test failures or repetitive debugging loops.
- **Key Invariants:** Three-Strikes Circuit Breaker: forces `git restore .`, invalidates failed hypotheses, resets to first principles.

### `flaky-test-isolation`
- **Purpose:** Diagnose and eliminate non-deterministic test failures caused by race conditions, unseeded randoms, state leakage, or clock skew.
- **Trigger:** Use when tests fail intermittently in CI or pass inconsistently.
- **Key Invariants:** 50x stress reproduction loop, inspection of the 4 culprits (state leak, clock skew, arbitrary sleep, unordered sets).

### `runtime-api-verification`
- **Purpose:** Introspect installed packages, verify method signatures, and inspect type definitions before invoking unfamiliar third-party library APIs.
- **Trigger:** Use when integrating third-party SDKs, upgrading dependencies, or resolving import errors.
- **Key Invariants:** Probing `inspect.signature()`, compiler `.d.ts` checks, running a 3-line probe script before application code.

---

## 3. Context Efficiency & Multi-Agent Operations

### `caveman`
- **Purpose:** Ultra-terse, high-density technical communication mode that reduces output tokens while preserving technical accuracy, exact commands, and safety warnings.
- **Trigger:** Use when concise responses or lower token consumption is desired.

### `context-compactor`
- **Purpose:** Distill extensive agent session transcripts into dense knowledge states, active hypothesis ledgers, and verified file citation indices.
- **Trigger:** Use when context windows approach limits or during multi-agent handoffs.

### `mcp-tool-designer`
- **Purpose:** Architect high-performance, type-safe Model Context Protocol (MCP) servers and tools with strict JSON schemas, token bounds, and idempotent annotations.
- **Trigger:** Use when designing MCP tools or building AI agent integrations.

### `agent-observability`
- **Purpose:** Instrument agent tool calls, prompt latency, token expenditure, and error boundaries with structured OpenTelemetry or JSON-L logging.
- **Trigger:** Use when debugging agent loops or optimizing multi-agent tracing.

### `human-in-the-loop`
- **Purpose:** Enforce explicit human approval boundaries before executing irreversible actions, deploying code, modifying schemas, or making external financial/data mutations.
- **Trigger:** Use when building safe autonomous agent workflows.

### `summarize`
- **Purpose:** Distill complex engineering documents, logs, and pull request diffs into structured executive summaries with citations and key architectural decisions.
- **Trigger:** Use when summarizing technical repositories or code reviews.

### `tavily-search`
- **Purpose:** Execute targeted web research across high-trust primary sources, official documentation, and technical repositories.
- **Trigger:** Use when researching cutting-edge library APIs, SDKs, or current industry standards.

### `self-improving-agent`
- **Purpose:** Extract concrete lessons and operational heuristics from runtime failures, user corrections, and test cycles into durable project memory.
- **Trigger:** Use when capturing recurring debugging patterns or user preferences.
