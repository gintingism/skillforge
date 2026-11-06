---
name: architecture-griller
description: Challenge architectural assumptions, stress-test system trade-offs, and record Architecture Decision Records (ADRs) before implementation. Use when designing new systems, evaluating RFCs, or debating technical trade-offs.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Pre-Implementation Architecture Grilling Protocol

Never jump straight into writing boilerplate for an unexamined design. Interrogate requirements, expose hidden coupling, and document explicit trade-offs before touching production code.

## Phase 1: Assumption & Constraint Interrogation
1. Identify the core problem statement and ask what happens if nothing is built.
2. Probe hard constraints across four boundaries:
   - Data volume and read/write ratio at 1x vs 10x scale.
   - Latency and failure tolerance (sync vs async, idempotency requirements).
   - Operational ownership (who debugs this when it pages at 03:00).
   - Existing repository primitives that already solve 80% of the requirement.
3. Ask the user 2 to 4 pointed, high-leverage questions to resolve ambiguities before proposing an implementation plan.

## Phase 2: Counter-Option Matrix
1. Formulate at least two distinct options:
   - **Option A (Minimal / Boring Stack):** Reuses existing database tables, queues, and monolith modules.
   - **Option B (Dedicated / Decoupled):** Introduces new schema boundaries, services, or external dependencies.
2. For each option, state the exact failure modes, migration cost, and rollback difficulty.

## Phase 3: Architecture Decision Record (ADR)
1. When a non-trivial design choice is finalized, record a concise ADR in `docs/adr/`.
2. Follow the canonical template in `references/adr-template.md` when drafting or reviewing ADR documents.
