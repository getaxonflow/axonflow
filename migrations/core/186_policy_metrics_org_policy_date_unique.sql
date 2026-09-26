-- Migration 186: policy_metrics gets the unique key its daily UPSERT names
-- Date: 2026-09-17
-- Purpose: The agent's shared-engine metrics write (platform/agent/audit_queue.go
--          flushMetricsBatch) is an UPSERT, one row per organization, policy and
--          day:
--            INSERT INTO policy_metrics (policy_id, policy_type, hit_count,
--              block_count, date, org_id) ... ON CONFLICT (...) DO UPDATE
--          migrations/core/010 created policy_metrics with only a PLAIN index on
--          (policy_id, date), so ON CONFLICT had no unique index to infer and the
--          statement failed with 42P10 on every write since the table was
--          created; the failure was swallowed by a log line, and the agent has
--          never written a metrics row (#4249).
--
-- THE KEY IS (org_id, policy_id, date), NOT (policy_id, date). policy_metrics is
-- row-level secured per organization (core/018: SELECT/INSERT/UPDATE/DELETE on
-- org_id = get_current_org_id()), and shared-engine policy ids are the same
-- for every organization (a system row's policy_id). On a global
-- (policy_id, date) key the first organization to write a policy's row on a
-- day would own it, and every other organization's UPSERT would conflict with
-- a row its UPDATE policy cannot see and fail: the same dropped write, with a
-- different error.
--
-- THE INDEX IS PARTIAL: WHERE policy_id IS NOT NULL. The orchestrator writes one
-- per-evaluation row (platform/orchestrator/db_dynamic_policies.go: policy_name
-- 'evaluation', execution_time_ms, success, tenant_id, org_id) and never sets
-- policy_id, and nothing trims those rows, so the table can be large. A partial
-- index holds only the agent's rows: it is small, costs the
-- orchestrator's INSERT no index write, and leaves that plain INSERT unchanged.
-- The agent's UPSERT names the same predicate (ON CONFLICT (org_id, policy_id,
-- date) WHERE policy_id IS NOT NULL), which is what lets Postgres infer it.
--
-- LOCKING. The agent's migration runner sends a file as one db.Exec of several
-- statements, which Postgres runs as a single implicit transaction, so
-- CONCURRENTLY is not available: CREATE UNIQUE INDEX takes a SHARE lock, which blocks writes to
-- policy_metrics (the orchestrator's per-evaluation INSERT, 2 s timeout, logged
-- and dropped) until the build finishes, and the build scans the whole table
-- for its predicate. Measure count(*) on the deployment before this release.
--
-- A LEGACY UNIQUE(policy_id, date). The retired init-rds.sh created
-- policy_metrics with that constraint, and core/010 is CREATE TABLE IF NOT
-- EXISTS, so a database initialized that way still has it, and a second
-- organization's UPSERT would fail on it (23505). The DO block below drops any
-- unique constraint or unique index on exactly (policy_id, date).
--
-- DUPLICATES. No writer in this tree could have produced two rows with one
-- non-NULL (org_id, policy_id, date): the agent's UPSERT never succeeded and the
-- orchestrator writes no policy_id. The migration still collapses any it finds
-- before creating the index, keeping the lowest id and summing hit_count,
-- block_count and allow_count into it, so it cannot fail on a database written
-- by some older build or by hand. Only rows whose three key columns are all
-- non-NULL are collapsed: a NULL in any of them is distinct to the index.
--
-- EDITION: COMMUNITY (mirrored). The agent's audit queue and policy_metrics
-- ship on every edition.
-- Related: #4249 row 5705939628; migrations/core/010, 018.

DO $$
DECLARE
    legacy record;
BEGIN
    FOR legacy IN
        SELECT c.conname AS name, 'constraint' AS kind
          FROM pg_constraint c
         WHERE c.conrelid = 'policy_metrics'::regclass
           AND c.contype = 'u'
           AND (SELECT array_agg(a.attname::text ORDER BY a.attname::text)
                  FROM unnest(c.conkey) k(attnum)
                  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum)
               = ARRAY['date', 'policy_id']
    LOOP
        EXECUTE format('ALTER TABLE policy_metrics DROP CONSTRAINT %I', legacy.name);
        RAISE NOTICE 'Migration 186: dropped the legacy unique constraint % on policy_metrics (policy_id, date)', legacy.name;
    END LOOP;
    FOR legacy IN
        SELECT ic.relname AS name
          FROM pg_index i
          JOIN pg_class ic ON ic.oid = i.indexrelid
         WHERE i.indrelid = 'policy_metrics'::regclass
           AND i.indisunique
           AND NOT i.indisprimary
           AND i.indpred IS NULL
           AND (SELECT array_agg(a.attname::text ORDER BY a.attname::text)
                  FROM unnest(i.indkey::int2[]) k(attnum)
                  JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum)
               = ARRAY['date', 'policy_id']
    LOOP
        EXECUTE format('DROP INDEX %I', legacy.name);
        RAISE NOTICE 'Migration 186: dropped the legacy unique index % on policy_metrics (policy_id, date)', legacy.name;
    END LOOP;
END $$;

WITH ranked AS (
    SELECT id,
           MIN(id) OVER (PARTITION BY org_id, policy_id, date) AS keep_id
      FROM policy_metrics
     WHERE org_id IS NOT NULL AND policy_id IS NOT NULL AND date IS NOT NULL
), totals AS (
    SELECT r.keep_id,
           SUM(COALESCE(m.hit_count, 0))   AS hit_count,
           SUM(COALESCE(m.block_count, 0)) AS block_count,
           SUM(COALESCE(m.allow_count, 0)) AS allow_count,
           COUNT(*)                        AS n
      FROM ranked r
      JOIN policy_metrics m ON m.id = r.id
     GROUP BY r.keep_id
    HAVING COUNT(*) > 1
)
UPDATE policy_metrics p
   SET hit_count = t.hit_count,
       block_count = t.block_count,
       allow_count = t.allow_count
  FROM totals t
 WHERE p.id = t.keep_id;

DELETE FROM policy_metrics p
 USING (
    SELECT id,
           MIN(id) OVER (PARTITION BY org_id, policy_id, date) AS keep_id
      FROM policy_metrics
     WHERE org_id IS NOT NULL AND policy_id IS NOT NULL AND date IS NOT NULL
 ) r
 WHERE p.id = r.id
   AND r.id <> r.keep_id;

CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_metrics_org_policy_date
    ON policy_metrics (org_id, policy_id, date)
    WHERE policy_id IS NOT NULL;
