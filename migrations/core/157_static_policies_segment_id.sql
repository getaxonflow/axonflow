-- Migration 157: static_policies.segment_id (ADR-060 #2989 P3)
-- Date: 2026-07-26
-- Issue: #3051, epic #2989
--
-- Adds an ORTHOGONAL, NULLABLE segment_id column to static_policies — the
-- P3 policy-targeting key. Decision 2 (LOCKED, see ADR-060 §"Combining
-- multiple segments" / §Phased-plan P3):
--   - segment_id is independent of `tier` — a policy is segment-scoped iff
--     segment_id IS NOT NULL, regardless of its tier (system/organization/
--     tenant). Do NOT add a tier='segment' value.
--   - segment_id holds the STABLE scim_groups.id (never display_name — an
--     admin rename must not silently re-target a policy authored against
--     the old identifier), scoped under the canonical org_id column (NOT
--     the deprecated organization_id / tenant_id columns — see #2791).
--   - NULL on every existing row = fully backward compatible: a policy
--     with segment_id IS NULL is unaffected by segment targeting and
--     matches exactly the pre-P3 selection semantics.
--
-- Core + nullable: inert in Community (no segment resolver there — P2's
-- IdentityAttributeResolver constructors return ErrEnterpriseOnly), and
-- exercised only when the enterprise-gated segment resolver populates a
-- non-empty resolved segment set.
--
-- Index rationale: the P3 selection query adds
--   AND (sp.segment_id IS NULL OR sp.segment_id = ANY($N::text[]))
-- to the existing tier-based WHERE on every effective-policy read (cached,
-- but still on the miss path of a per-request hot path) — index the column
-- so a segment lookup on a large policy table isn't a sequential scan.
-- Partial (WHERE segment_id IS NOT NULL) since the column is NULL on the
-- overwhelming majority of rows (every pre-P3 policy, and every org that
-- never authors a segment-scoped policy).
--
-- Idempotency: ADD COLUMN IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.
-- Re-runs are no-ops.
--
-- Rollback: paired 157_static_policies_segment_id_down.sql drops the
-- column + index. Purely additive forward migration, loss-free at the
-- schema level for every pre-P3 row (segment_id is NULL on all of them).
--
-- Depends on: 010_policy_tables (static_policies), 090_v9_policy_tables_client_id
-- (org_id / client_id columns this column is scoped alongside).

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'static_policies') THEN
        ALTER TABLE static_policies
            ADD COLUMN IF NOT EXISTS segment_id VARCHAR(255);

        CREATE INDEX IF NOT EXISTS idx_static_policies_segment
            ON static_policies(org_id, segment_id)
            WHERE segment_id IS NOT NULL;

        RAISE NOTICE 'Migration 157: static_policies.segment_id added (nullable, backward compatible)';
    ELSE
        RAISE NOTICE 'Migration 157: static_policies missing — skipping';
    END IF;
END $$;

-- Column documentation.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'static_policies' AND column_name = 'segment_id') THEN
        EXECUTE 'COMMENT ON COLUMN static_policies.segment_id IS ''ADR-060 (#2989) governance-segment targeting key: the stable scim_groups.id, scoped under org_id. NULL = not segment-scoped (backward-compatible default, independent of tier). Never the deprecated organization_id/tenant_id columns, never scim_groups.display_name.''';
    END IF;
END $$;

-- Self-test: the column must be nullable and every existing row must be
-- untouched (still NULL) — this migration only ADDS a column, it never
-- writes to it, so a non-zero non-null count here would mean something
-- else (a stray backfill, a re-run against a dirtied dev DB) touched the
-- column outside this migration's own idempotent no-op path.
DO $$
DECLARE
    is_nullable TEXT;
    non_null_count INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'static_policies') THEN
        SELECT c.is_nullable INTO is_nullable
        FROM information_schema.columns c
        WHERE c.table_name = 'static_policies' AND c.column_name = 'segment_id';

        IF is_nullable IS DISTINCT FROM 'YES' THEN
            RAISE EXCEPTION 'Migration 157 failed: static_policies.segment_id must be nullable, got is_nullable=%', is_nullable;
        END IF;

        SELECT COUNT(*) INTO non_null_count FROM static_policies WHERE segment_id IS NOT NULL;
        IF non_null_count > 0 THEN
            RAISE NOTICE 'Migration 157: % static_policies rows already carry a segment_id (pre-existing data, not written by this migration)', non_null_count;
        END IF;
    END IF;
END $$;

COMMIT;
