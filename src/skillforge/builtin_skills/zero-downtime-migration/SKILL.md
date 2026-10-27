---
name: zero-downtime-migration
description: Plan and execute non-breaking database schema changes, table reorganizations, and API payload updates using the Expand-Contract pattern. Use when modifying SQL tables, ORM models, or public API endpoints in production systems.
license: MIT
compatibility: SQL (Postgres, MySQL, SQLite), Alembic, Prisma, Django ORM
metadata:
  version: "1.0.0"
  author: "SkillForge Team"
---

# Zero-Downtime Migration Protocol (Expand-Contract)

In-place schema edits and breaking API renames cause immediate production downtime when running multiple application instances during rolling deployments. Follow the four-phase Expand-Contract pattern.

## The 4 Migration Phases

### Phase 1: Expand (Dual-Write)
1. Add new columns as **nullable** (`NULL`) or with an instant default (e.g. Postgres 11+ metadata defaults).
2. Never rename or drop existing columns in this phase.
3. Update application code to **write to both** the old and new columns, but continue reading from the old column.
4. Deploy Phase 1 code safely.

### Phase 2: Backfill (Async Batching)
1. Write an idempotent batch script to copy historic data from the old column to the new column.
2. Backfill in chunks (e.g., 1,000–5,000 rows per transaction with sleep intervals) to prevent holding table locks or starving connection pools.
3. Verify that 100% of rows match between old and new storage.

### Phase 3: Switch Reads
1. Update application code to read from the new column, with a fallback to the old column if null.
2. Maintain dual-writes.
3. Monitor application logs and query performance metrics for regressions.

### Phase 4: Contract (Cleanup)
1. Once all deployed instances read exclusively from the new column and telemetry confirms zero queries hit the old schema:
   - Stop writing to the old column.
   - Drop foreign key constraints on the old column.
   - Schedule a safe migration to drop the old column or mark the old API field as deprecated.

## Forbidden Anti-Patterns
- `ALTER TABLE ... RENAME COLUMN`: Breaks all running pods/instances immediately.
- Adding `NOT NULL` on a multi-million-row table without backfill.
- Long-running migrations inside an active application startup hook.
