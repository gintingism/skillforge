# SQL Indexing & DDL Lock Anti-Patterns

## 1. Composite Index Column Ordering
Order composite B-Tree index columns by:
1. **Equality predicates** (`WHERE tenant_id = $1 AND status = 'active'`) first.
2. **Sort or range predicates** (`AND created_at > $2 ORDER BY created_at DESC`) second.

Placing a range column first prevents B-Tree index lookup on subsequent equality columns.

## 2. Leading Wildcards & Function-Wrapped Columns
- **Anti-pattern:** `WHERE LOWER(email) = $1` or `WHERE name LIKE '%smith'` bypasses standard B-Tree indexes.
- **Fix:** Use an expression index (`CREATE INDEX ON users (LOWER(email))`) or trigram `GIN` index (`pg_trgm`) for substring searches.

## 3. Blocking DDL Operations in PostgreSQL
- Adding a column with a volatile default or running `ALTER TABLE ... ADD CONSTRAINT ... FOREIGN KEY` acquires an `ACCESS EXCLUSIVE` lock during validation.
- **Fix:** Add foreign keys with `NOT VALID` first, then run `VALIDATE CONSTRAINT` in a separate transaction.
