-- Migration 102: post-FORCE-RLS hardening on the customer-facing audit tables
-- Date: 2026-05-20
--
-- Three latent issues that are inert today but compound the FORCE-RLS surface
-- area going forward. Surfaced during the v9 backfill sweep.
--
-- Three independent hardening steps:
--
-- 1. DROP audit_retention_config_admin_access policy
--    Migration 026 created TWO permissive policies on audit_retention_config:
--      - audit_retention_config_org_isolation (USING org_id = current_setting('app.current_org_id', true))
--      - audit_retention_config_admin_access  (USING current_setting('app.is_admin', true)::BOOLEAN = true)
--    Postgres OR-combines permissive policies for the same command. Post-101
--    FORCE RLS, any session that issues `SET app.is_admin = true` reads ALL
--    orgs' rows — bypassing the org-isolation policy.
--    Today no Go code sets `app.is_admin` (grepped: only 2 SQL refs, both in
--    migrations) so the policy is dormant. The architectural contract is
--    explicit that cross-org work belongs on axonflow_platform_admin
--    (BYPASSRLS), not on a GUC backdoor. Drop the policy to enforce that
--    contract.
--
-- 2. Normalize decision_chain_org_isolation policy expression
--    Migration 025 created decision_chain_org_isolation with USING shape
--    `(org_id = get_current_org_id())` — calling the SQL helper defined in 018.
--    Functionally equivalent to current_setting(...), but the smoke
--    verification block in 101 uses `qual LIKE '%app.current_org_id%'` which
--    does NOT match the helper-function form. The smoke check therefore has a
--    silent false-negative for decision_chain: GROUP BY returns zero rows, the
--    LOOP body never executes, RAISE EXCEPTION never fires. Migration 101
--    "succeeded" but the smoke contract didn't actually validate.
--    Normalize to the direct current_setting form so future migrations can
--    grep `pg_policies.qual` reliably + so the policy expression matches
--    sibling tables.
--
-- 3. ADD NOT NULL constraint on mcp_query_audits.org_id
--    Schema state pre-102:
--      - audit_retention_config.org_id  — NOT NULL ✅ (mig 026 CREATE TABLE)
--      - decision_chain.org_id          — NOT NULL ✅ (mig 025 CREATE TABLE)
--      - mcp_query_audits.org_id        — NULLABLE (mig 061 ADD COLUMN, never set NOT NULL)
--    Migration 094 backfilled remaining NULL org_id rows via Pass-1D (cs_*) +
--    Pass-2 (deployment_org). FORCE RLS WITH CHECK rejects NULL inserts going
--    forward. But the schema constraint should match the invariant the
--    migration depends on; otherwise a future ALTER could re-introduce NULL.
--    Verify no NULL rows remain, then SET NOT NULL.

BEGIN;

-- ============================================================================
-- Step 1: drop the latent app.is_admin backdoor policy
-- ============================================================================
DROP POLICY IF EXISTS audit_retention_config_admin_access ON audit_retention_config;

COMMENT ON TABLE audit_retention_config IS
    'Per-org retention config. Migration 102 dropped the legacy '
    'app.is_admin admin_access policy. Cross-org access is now via '
    'axonflow_platform_admin (BYPASSRLS).';

-- ============================================================================
-- Step 2: normalize decision_chain_org_isolation to the direct current_setting form
-- ============================================================================
-- Use DROP+CREATE to overwrite the original 025 policy expression.
DROP POLICY IF EXISTS decision_chain_org_isolation ON decision_chain;
CREATE POLICY decision_chain_org_isolation ON decision_chain
    FOR ALL
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

COMMENT ON POLICY decision_chain_org_isolation ON decision_chain IS
    'Per-org row visibility. Migration 102 normalized the expression from '
    'get_current_org_id() (mig 025) to direct current_setting() so '
    'smoke-verification grep on pg_policies.qual matches.';

-- ============================================================================
-- Step 3: assert + enforce NOT NULL on mcp_query_audits.org_id
-- ============================================================================
DO $$
DECLARE
    null_count BIGINT;
    is_not_null BOOLEAN;
BEGIN
    -- Skip if table doesn't exist (community-only builds without SaaS schema).
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mcp_query_audits') THEN
        RAISE NOTICE 'Migration 102 Step 3: mcp_query_audits does not exist — skipping NOT NULL enforcement';
        RETURN;
    END IF;

    -- Skip if already NOT NULL (idempotency).
    SELECT (is_nullable = 'NO') INTO is_not_null
    FROM information_schema.columns
    WHERE table_name = 'mcp_query_audits' AND column_name = 'org_id';

    IF is_not_null THEN
        RAISE NOTICE 'Migration 102 Step 3: mcp_query_audits.org_id is already NOT NULL — skipping';
        RETURN;
    END IF;

    -- Defensive: count NULL/empty rows. Migration 094 Pass-2 should have caught
    -- everything, but check before adding the constraint.
    SELECT COUNT(*) INTO null_count
    FROM mcp_query_audits
    WHERE org_id IS NULL OR org_id = '';

    IF null_count > 0 THEN
        RAISE EXCEPTION 'Migration 102 Step 3: mcp_query_audits has % rows with NULL or empty org_id; '
                        'migration 094 backfill did not cover them. Investigate before re-running.', null_count;
    END IF;

    -- Safe to add the constraint.
    EXECUTE 'ALTER TABLE mcp_query_audits ALTER COLUMN org_id SET NOT NULL';
    RAISE NOTICE 'Migration 102 Step 3: mcp_query_audits.org_id NOT NULL constraint enforced';
END
$$;

-- ============================================================================
-- Smoke verification (improved over 100's structurally-broken loop)
-- ============================================================================
DO $$
DECLARE
    bad_table TEXT;
BEGIN
    -- For each of the 3 customer-facing audit tables, assert at least one policy whose qual
    -- references either current_setting('app.current_org_id', ...) directly
    -- OR get_current_org_id() (the helper that wraps it). Either form is
    -- semantically valid; we only fail if neither matches.
    --
    -- Use NOT EXISTS subquery — unlike 100's GROUP BY loop, this fires
    -- correctly when a table has ZERO matching policies.
    FOR bad_table IN
        SELECT t.tname
        FROM (VALUES ('mcp_query_audits'),
                     ('audit_retention_config'),
                     ('decision_chain')) AS t(tname)
        WHERE NOT EXISTS (
            SELECT 1 FROM pg_policies p
            WHERE p.tablename = t.tname
              AND (p.qual LIKE '%app.current_org_id%'
                   OR p.qual LIKE '%get_current_org_id%')
        )
    LOOP
        RAISE EXCEPTION 'Migration 102 verification: % has no org_id-isolation policy after hardening', bad_table;
    END LOOP;

    -- Assert FORCE RLS still active (sanity post-101 — nothing in 101 should
    -- have disturbed it, but the smoke check is cheap insurance).
    FOR bad_table IN
        SELECT relname FROM pg_class
        WHERE relname IN ('mcp_query_audits', 'audit_retention_config', 'decision_chain')
          AND (NOT relrowsecurity OR NOT relforcerowsecurity)
    LOOP
        RAISE EXCEPTION 'Migration 102 verification: % lost FORCE RLS state', bad_table;
    END LOOP;

    RAISE NOTICE 'Migration 102 verified: 3 audit tables hardened (admin_access dropped, decision_chain policy normalized, mcp_query_audits.org_id NOT NULL)';
END
$$;

COMMIT;
