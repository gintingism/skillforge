# Built-in Skills Catalog

SkillForge includes 32 production-grade engineering skills designed to resolve common agent failure modes identified in autonomous coding benchmarks.

All built-in skills comply with the Progressive Disclosure Standard (`QUAL-003`), carry zero AI filler, and pass full static security audits (`100/100`).

---

## Installation of Built-in Skills

Install any built-in skill directly into your current workspace:

```bash
skillforge install systematic-debugging
```

Or install it globally to your user profile across all detected coding assistants:

```bash
skillforge install systematic-debugging --global
```

---

## Category 1: Code Quality, Security & Performance (16 Skills)

| Skill Name | Purpose & Primary Triggers | References & Assets |
| :--- | :--- | :--- |
| `supply-chain-sentinel` | Inspects package registries, verify release age, and run CVE audits (`pip-audit`, `npm audit`) before adding dependencies. | `references/registry-heuristics.md` |
| `secret-sanitizer` | Pre-commit git diff auditor that prevents API keys, private tokens, and credentials from leaking into commits. | Built-in regex engine |
| `contract-test-generator` | Authors property-based invariant tests and contract fuzz tests using Hypothesis and fast-check. | `references/contract-patterns.md` |
| `blast-radius-containment` | Traces upstream references and enforces a strict file touch budget before modifying shared libraries or core APIs. | `references/radius-checklist.md` |
| `security-threat-modeler` | Maps trust boundaries, checks IDOR/BOLA authorization, validates SSRF risks, and audits injection sinks. | `references/owasp-top-10.md` |
| `performance-profiler` | Enforces baseline-first benchmarking (`p50`/`p95`/`p99`), N+1 query detection, and algorithmic complexity checks before optimizing. | `references/profiling-checklist.md` |
| `antislop-code` | Code comment hygiene and anti-overengineering filters that strip redundant narrative comments and speculative generality. | `references/clean-code-rules.md` |
| `spec-driven-development` | Enforces schema-first API specifications and red-green verification loops before implementing logic. | `references/openapi-spec-rules.md` |
| `zero-downtime-migration` | Applies the four-phase Expand-Contract pattern for non-breaking database schema and API contract evolutions. | `references/expand-contract.md` |
| `code-review` | Multi-pass adversarial review matrix covering correctness, security, performance, and test integrity. | `references/review-matrix.md` |
| `git-workflow` | Atomic conventional commits, pre-staging diff checks, protected branch safety guardrails, and conflict pause protocol. | `references/conventional-commits.md` |
| `test-driven-development` | Strict Red-Green-Refactor development cycle with test runner discovery and failing reproduction assertions. | `references/tdd-cycle.md` |
| `dependency-upgrade` | Systematic version updates with changelog and CVE audits, incremental single-package bumps, and rollback safeguards. | `references/upgrade-protocol.md` |
| `architecture-griller` | Pre-implementation design interrogation, trade-off matrix analysis, and Architecture Decision Record (ADR) authoring. | `references/adr-template.md` |
| `browser-qa-verifier` | Live headless browser QA with Playwright/DevTools, console/network error listeners, and accessible locator rules. | `references/playwright-checklist.md` |
| `database-query-safety` | SQL execution plan (`EXPLAIN ANALYZE`) auditing, composite B-Tree index ordering, and Row-Level Security (RLS) checks. | `references/sql-anti-patterns.md` |

---

## Category 2: Autonomous Loop Stability & Debugging (7 Skills)

| Skill Name | Purpose & Primary Triggers | References & Assets |
| :--- | :--- | :--- |
| `systematic-debugging` | Four-phase diagnosis protocol: Reproduce, Isolate, Hypothesize, Surgical Patch. Prevents speculative trial-and-error editing. | `references/root-cause-tree.md` |
| `cognitive-loop-breaker` | Three-strikes circuit breaker that forces a hard `git restore` and hypothesis invalidation when stuck in repetitive edit-fail loops. | `references/circuit-breaker-rules.md` |
| `flaky-test-isolation` | Stress-reproduction loop (50x iterations) and diagnosis protocol for race conditions, clock skew, and state leakage. | `references/flaky-taxonomy.md` |
| `runtime-api-verification` | Interactive runtime signature introspection (`inspect`, `dir()`, compiler definitions) to prevent hallucinated arguments. | `references/introspection-guide.md` |
| `git-worktree-isolation` | Manage isolated git worktrees for parallel agent tasks, speculative bug fixes, and clean branch exploration. | `references/worktree-cleanup-protocol.md` |
| `atomic-rollback-guard` | Enforce atomic checkpointing before destructive code mutations and trigger automated hard rollbacks on test regression. | `references/rollback-decision-tree.md` |
| `traceback-postmortem` | Extract structured root-cause postmortems from long stack traces and test failure dumps to prevent context poisoning. | `references/5-whys-template.md` |

---

## Category 3: Context Efficiency & Multi-Agent Operations (9 Skills)

| Skill Name | Purpose & Primary Triggers | References & Assets |
| :--- | :--- | :--- |
| `skill-architect` | Multi-file progressive disclosure guide for authoring low-token `SKILL.md`, `AGENTS.md`, and `CLAUDE.md` files. | `references/progressive-disclosure.md` |
| `caveman` | Terse technical communication mode that eliminates fluff while preserving exact paths, commands, and raw errors. | Built-in voice rules |
| `context-compactor` | Structured state distillation and active hypothesis ledgers for long-running agent threads nearing context limits. | `references/compaction-schema.md` |
| `mcp-tool-designer` | Type-safe schema design, idempotent hints, token boundaries, and stderr error separation for MCP servers. | `references/mcp-schema-template.md` |
| `agent-observability` | OpenTelemetry tracing standards, step timing, and 16KB payload truncation boundaries for agent tool calls. | `references/telemetry-schema.md` |
| `human-in-the-loop` | Three-tier permission model separating read-only queries from irreversible actions. | `references/permission-levels.md` |
| `summarize` | Executive engineering summaries with exact file and line citations. | `references/citation-format.md` |
| `tavily-search` | Authoritative primary-source technical research with cross-verification. | `references/verification-rules.md` |
| `self-improving-agent` | Error recording loop that turns recurring bugs into durable project rules. | `references/rule-extraction.md` |
