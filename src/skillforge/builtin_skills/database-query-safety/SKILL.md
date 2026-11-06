---
name: database-query-safety
description: Audit SQL queries, execution plans (EXPLAIN ANALYZE), index coverage, table lock risks, and Row-Level Security (RLS) policies. Use when writing database queries, optimizing slow SQL, or designing relational schemas.
license: MIT
compatibility: Universal
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Database Query Safety & Indexing Protocol

Prevent production table locks, full-table sequential scans, and cross-tenant data leaks before SQL reaches production.

## Phase 1: Parameterization & Tenant Isolation
1. Verify all user-supplied values use parameterized placeholders (`$1`, `?`, `:param`); reject string interpolation in SQL builders.
2. Confirm multi-tenant queries filter explicitly by tenant/organization ID or enforce Row-Level Security (RLS) policies on every table.
3. Verify RLS policies include both `USING` (for `SELECT`/`UPDATE`/`DELETE`) and `WITH CHECK` (for `INSERT`/`UPDATE`) clauses.

## Phase 2: Execution Plan & Index Audit
1. Inspect query predicates (`WHERE`, `JOIN`, `ORDER BY`) against existing index definitions.
2. Run `EXPLAIN (ANALYZE, BUFFERS)` on non-trivial queries and verify index scans replace sequential scans on high-cardinality tables.
3. Enforce bounded pagination (cursor/keyset pagination preferred over large `OFFSET` scans).
4. Review `references/sql-anti-patterns.md` for composite index column ordering and DDL lock avoidance.

## Phase 3: Safe DDL & Lock Timeout Guardrails
1. Set explicit `lock_timeout` and `statement_timeout` before running DDL alterations.
2. Create indexes concurrently (`CREATE INDEX CONCURRENTLY` in PostgreSQL) on live tables to avoid blocking writes.
