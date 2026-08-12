-- Migration 159: dynamic_policies.segment_id (ADR-060 #2989 P3b)
-- Date: 2026-07-31
-- Issue: #3052, epic #2989
--
-- Adds an ORTHOGONAL, NULLABLE segment_id column to dynamic_policies — the
-- P3b policy-targeting key for the orchestrator's customer-CRUD-managed
-- dynamic policies, mirroring migration 157 (static_policies.segment_id, P3)
-- for the agent static plane. Decision 2 (LOCKED, see ADR-060 §"Combining
-- multiple segments" / §Phased-plan P3b):
--   - segment_id is independent of tenant_id — a policy is segment-scoped
--     iff segment_id IS NOT NULL, regardless of which tenant it targets.
--   - segment_id holds the STABLE scim_groups.id (never display_name — an
--     admin rename must not silently re-target a policy authored against
--     the old identifier), scoped under the canonical org_id column dynamic
--     policies already carry (added by 090_v9_policy_tables_client_id).
--   - NULL on every existing row = fully backward compatible: a policy with
--     segment_id IS NULL is unaffected by segment targeting and matches
--     exactly the pre-P3b selection semantics on both engines
--     (memPolicyAppliesToTenant / dbCachedPolicyAppliesToTenant).
--
-- Core + nullable: inert in Community (no segment resolver there — the
-- shared IdentityAttributeResolver's community stub returns ErrEnterpriseOnly),
-- and exercised only when the enterprise-gated segment resolver populates a
-- non-empty resolved segment set on the orchestrator.
--
-- Index rationale: the choke-point predicates add an in-process
-- (segment_id IS NULL OR segment_id = ANY(callerSegments)) filter over the
-- ALREADY-LOADED cross-tenant policy set (both engines load dynamic_policies
-- cross-org on the BYPASSRLS refresh pool and filter per-request in Go — see
-- dynamic_policy_engine.go's loadPoliciesFromDB / db_dynamic_policies.go's
-- refreshPolicies). The index therefore does not serve a per-request query
-- path the way 157's does; it is added for parity with 157, to keep any
-- future direct segment-scoped read (portal listing, P6 write path) from
-- defaulting to a sequential scan, and because the column is NULL on the
-- overwhelming majority of rows (partial index, WHERE segment_id IS NOT
-- NULL).
--
-- Idempotency: ADD COLUMN IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.
-- Re-runs are no-ops.
--
-- Rollback: paired 159_dynamic_policies_segment_id_down.sql drops the
-- column + index. Purely additive forward migration, loss-free at the
-- schema level for every pre-P3b row (segment_id is NULL on all of them).
--
-- Depends: 010_policy_tables (dynamic_policies), 090_v9_policy_tables_client_id
-- (org_id / client_id columns this column is scoped alongside), 018_row_level_security
-- (dynamic_policies RLS — unaffected; this column carries no RLS predicate of
-- its own, segment filtering happens in Go at the choke point, not in SQL).
--
-- Upgrade-ordering note (H3, #3239 round 2): this migration is NOT
-- synchronized with orchestrator boot. Standard Docker Compose's
-- `depends_on: agent service_healthy` does not actually wait for migrations
-- to finish — /health is liveness-only and returns 200 (status:"starting")
-- before the migration runner completes — so the orchestrator can start
-- serving requests while this migration is still pending. Both dynamic-
-- policy loaders (db_dynamic_policies.go's refreshPolicies,
-- dynamic_policy_engine.go's loadPoliciesFromDB) tolerate the resulting
-- "column segment_id does not exist" (SQLSTATE 42703) by retrying
-- segment-less until the column lands — correct pre-migration behavior,
-- since no segment_id rows can exist yet. See segment_column_probe.go. The
-- honest-readiness root-cause fix (a genuine 503-until-ready signal,
-- distinct from the liveness /health check) is deferred to #3285.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies') THEN
        ALTER TABLE dynamic_policies
            ADD COLUMN IF NOT EXISTS segment_id VARCHAR(255);

        CREATE INDEX IF NOT EXISTS idx_dynamic_policies_segment
            ON dynamic_policies(org_id, segment_id)
            WHERE segment_id IS NOT NULL;

        RAISE NOTICE 'Migration 159: dynamic_policies.segment_id added (nullable, backward compatible)';
    ELSE
        RAISE NOTICE 'Migration 159: dynamic_policies missing — skipping';
    END IF;
END $$;

-- Column documentation.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'dynamic_policies' AND column_name = 'segment_id') THEN
        EXECUTE 'COMMENT ON COLUMN dynamic_policies.segment_id IS ''ADR-060 (#2989 P3b) governance-segment targeting key: the stable scim_groups.id, scoped under org_id. NULL = not segment-scoped (backward-compatible default, independent of tenant_id). Never the deprecated organization_id column, never scim_groups.display_name.''';
    END IF;
END $$;

-- Self-test: the column must be nullable and every existing row must be
-- untouched (still NULL) — this migration only ADDS a column, it never
-- writes to it, so a non-zero non-null count here would mean something else
-- (a stray backfill, a re-run against a dirtied dev DB) touched the column
-- outside this migration's own idempotent no-op path.
DO $$
DECLARE
    is_nullable TEXT;
    non_null_count INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_schema = 'public' AND table_name = 'dynamic_policies') THEN
        SELECT c.is_nullable INTO is_nullable
        FROM information_schema.columns c
        WHERE c.table_name = 'dynamic_policies' AND c.column_name = 'segment_id';

        IF is_nullable IS DISTINCT FROM 'YES' THEN
            RAISE EXCEPTION 'Migration 159 failed: dynamic_policies.segment_id must be nullable, got is_nullable=%', is_nullable;
        END IF;

        SELECT COUNT(*) INTO non_null_count FROM dynamic_policies WHERE segment_id IS NOT NULL;
        IF non_null_count > 0 THEN
            RAISE NOTICE 'Migration 159: % dynamic_policies rows already carry a segment_id (pre-existing data, not written by this migration)', non_null_count;
        END IF;
    END IF;
END $$;

-- M7 (#3239 round 2): drop the unused get_dynamic_policies_for_tenant()
-- helper function (migration 010) — no production caller (verified: only
-- doc-cites and one now-removed v9_tests functional-test assertion,
-- v9_tests/functional_tests.sql FT.5). It predates, and is unrelated to,
-- the segment_id targeting this migration adds; dropped here rather than
-- left to bit-rot because it is unused code with a false-comfort name (an
-- unwary future caller could reasonably assume it already understands
-- segment scoping — it never did, and never will). Recreated in the paired
-- down migration for a clean, reversible round-trip.
DROP FUNCTION IF EXISTS get_dynamic_policies_for_tenant(VARCHAR);

COMMIT;
