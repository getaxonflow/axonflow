-- Migration 096: schema_migrations dedup key = (version, name), not version alone
-- Date: 2026-05-19
-- Depends: 001_schema_migrations
--
-- ============================================================================
-- Bug being fixed
-- ============================================================================
--
-- migrations/core/001_schema_migrations.sql created schema_migrations with
--   `version VARCHAR(20) NOT NULL UNIQUE`
-- and the Go runner at platform/agent/migration_helpers.go::getAppliedMigrations
-- + platform/agent/run.go:705-714 dedups against `version` alone.
--
-- Several migration files SHARE a version prefix:
--   core/025_decision_chain.sql              core/025_hitl_oversight_queue.sql
--   core/042_singapore_pii_patterns.sql      core/042_unified_execution_history.sql
--   core/059_dangerous_command_policies.sql  core/059_runtime_tables_to_migrations.sql
--   core/076_community_saas_recovery_tokens.sql
--                                            core/076_critical_system_policies_no_override.sql
--   core/085_community_saas_bridge_pg_readonly.sql
--                                            community-saas/085_community_saas_bridge_pg_readonly.sql
--
-- On a fresh install, all files get applied in alphabetical order and the
-- UNIQUE constraint quietly trips when the second 025 (etc.) is recorded:
-- the ON CONFLICT clause in recordMigrationSuccess UPDATEs the existing row
-- instead of inserting a new one. The schema effects ran, but schema_migrations
-- forgets that — so re-running the agent against the same DB SKIPS the second
-- 025 because the version key already exists, and any post-fact correction
-- migration shipped under the same version number is silently dropped.
--
-- This is a silent correctness bug. Specific past-impact examples:
--   * hitl_oversight_queue: tracked as a separate migration but its
--     schema_migrations row gets overwritten by decision_chain.
--   * critical_system_policies_no_override: ditto for the recovery_tokens
--     row.
-- The two 085 files are byte-identical (relocation artifact: see
-- platform/agent/migration_helpers.go:137-144), so 085 is duplicate-but-safe;
-- the in-core/ collisions are the high-risk class.
--
-- ============================================================================
-- Fix
-- ============================================================================
--
-- 1. Drop the UNIQUE constraint on `version`.
-- 2. Add UNIQUE constraint on `(version, name)` — both columns already exist
--    and are NOT NULL, so the composite is well-defined.
-- 3. Backfill: any historical row that overwrote a sibling on the same
--    version still has a single (version, name) tuple, so the composite
--    constraint is satisfied by construction. No data fix needed.
-- 4. Drop the redundant `idx_schema_migrations_version` plain index in favor
--    of the composite UNIQUE index (which doubles as a fast lookup).
--
-- Idempotent: every clause guards with IF EXISTS / IF NOT EXISTS.
-- Safe to re-run.
--
-- Post-migration: Go runner code change (in the same PR) must:
--   - getAppliedMigrations: return `map[string]bool` keyed by `version + "/" + name`.
--   - run.go: index into appliedMigrations by the same composite key.
--   - recordMigrationSuccess / recordMigrationFailure: ON CONFLICT (version, name).
--
-- ============================================================================

DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    -- 1. Find and drop ANY UNIQUE constraint on `version` alone. We don't
    -- assume the constraint name because Postgres auto-generates it from
    -- table+column when CREATE TABLE declared the column UNIQUE inline
    -- (which 001 does). pg_constraint.conkey is an int2vector of column
    -- positions; pg_attribute maps positions to names.
    SELECT con.conname INTO constraint_name
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
    WHERE rel.relname = 'schema_migrations'
      AND nsp.nspname = 'public'
      AND con.contype = 'u'              -- UNIQUE
      AND array_length(con.conkey, 1) = 1
      AND (
          SELECT attname FROM pg_attribute
          WHERE attrelid = con.conrelid AND attnum = con.conkey[1]
      ) = 'version'
    LIMIT 1;

    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE schema_migrations DROP CONSTRAINT %I', constraint_name);
        RAISE NOTICE 'Dropped UNIQUE(version) constraint: %', constraint_name;
    ELSE
        RAISE NOTICE 'No UNIQUE(version)-only constraint found on schema_migrations (already migrated or fresh install)';
    END IF;
END $$;

-- 2. Add the composite UNIQUE constraint. Guard against a fresh install
-- that already has the composite (the migration is idempotent and may be
-- re-applied via the Go runner during recovery). The EXCEPTION block
-- handles the concurrent-boot race where a peer agent landed the same
-- ADD CONSTRAINT between our IF check and our ALTER (SQLSTATE 42710 /
-- duplicate_object).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        WHERE rel.relname = 'schema_migrations'
          AND con.contype = 'u'
          AND array_length(con.conkey, 1) = 2
    ) THEN
        BEGIN
            ALTER TABLE schema_migrations
                ADD CONSTRAINT schema_migrations_version_name_uniq
                UNIQUE (version, name);
            RAISE NOTICE 'Added UNIQUE(version, name) constraint';
        EXCEPTION WHEN duplicate_object THEN
            RAISE NOTICE 'UNIQUE(version, name) added by concurrent peer between IF check and ALTER';
        END;
    ELSE
        RAISE NOTICE 'UNIQUE(version, name) composite constraint already present';
    END IF;
END $$;

-- 3. Drop the now-redundant plain version index. The composite UNIQUE
-- automatically backs a btree on (version, name), which Postgres can
-- still use for version-prefix lookups.
DROP INDEX IF EXISTS idx_schema_migrations_version;

COMMENT ON CONSTRAINT schema_migrations_version_name_uniq ON schema_migrations IS
'Composite dedup key for migration files. See 096_schema_migrations_dedup_composite.sql for the bug context — version alone collided across same-prefix files like 025_decision_chain.sql + 025_hitl_oversight_queue.sql.';

-- Register this migration. The Go runner will do the same after it runs,
-- but recording here makes the migration self-describing and survives even
-- if a future operator reruns 001 (which is no-op idempotent).
INSERT INTO schema_migrations (version, name, applied_at, success) VALUES
    ('096', 'schema_migrations_dedup_composite', NOW(), true)
ON CONFLICT (version, name) DO NOTHING;
