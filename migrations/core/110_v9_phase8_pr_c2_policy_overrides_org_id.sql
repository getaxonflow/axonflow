-- Migration 110: normalize policy_overrides RLS to app.current_org_id
-- Date: 2026-05-22
--
-- ============================================================================
-- Why
-- ============================================================================
-- platform/orchestrator/overrides_handler.go INSERTs into policy_overrides at
-- two paths (create + revoke). Under axonflow_app_role (NOBYPASSRLS) every
-- write hits the table's RLS policy. mig 030 created the policy keyed on
-- `current_setting('app.tenant_id', true)` — the LEGACY GUC namespace. The
-- canonical GUC is `app.current_org_id`, set by
-- platform/agent/rls_session.go::WithOrgScope. No code path sets app.tenant_id
-- anymore (migs 105/106 removed the last setters).
-- Without normalization, every write under app_role would silently no-op (USING
-- evaluates to FALSE; INSERT with USING-as-WITH-CHECK rejects with 42501).
--
-- Same shape applies to static_policy_versions (mig 030, line 145) — also
-- keyed on app.tenant_id via its parent static_policies subquery. Included
-- here for the same reason.
--
-- ============================================================================
-- Scope
-- ============================================================================
-- 1. ADD COLUMN policy_overrides.org_id VARCHAR(255) (nullable for backfill).
-- 2. Backfill org_id from organizations table where organization_id (UUID)
--    matches, else from tenants.org_id by tenant_id, else fall back to the
--    tenant_id value verbatim (legacy tenant_id==org_id collapse).
-- 3. DROP the legacy policy + CREATE a new policy keyed on app.current_org_id
--    against the new org_id column (canonical shape, mirrors mig 105/106/107).
-- 4. Same treatment for static_policy_versions — the parent subquery now
--    consults static_policies.org_id matched against app.current_org_id.
--    static_policies already has org_id (mig 010).
--
-- ============================================================================
-- Idempotency
-- ============================================================================
-- ADD COLUMN IF NOT EXISTS + UPDATE WHERE NULL + DROP POLICY IF EXISTS
-- + CREATE POLICY are all idempotent on re-run.

BEGIN;

-- ============================================================================
-- Step 1: policy_overrides — add org_id, backfill, switch policy
-- ============================================================================
DO $$
DECLARE
    null_rows INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'policy_overrides') THEN
        ALTER TABLE policy_overrides ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);
        RAISE NOTICE 'Migration 110: ensured org_id on policy_overrides';

        -- Backfill chain (in priority order):
        --   1. organizations table where organization_id UUID matches
        --   2. tenants table where tenant_id matches
        --   3. legacy collapse fallback: tenant_id == org_id
        UPDATE policy_overrides po
        SET org_id = o.org_id
        FROM organizations o
        WHERE po.org_id IS NULL
          AND po.organization_id IS NOT NULL
          AND o.id::text = po.organization_id::text;

        UPDATE policy_overrides po
        SET org_id = t.org_id
        FROM tenants t
        WHERE po.org_id IS NULL
          AND po.tenant_id IS NOT NULL
          AND t.tenant_id = po.tenant_id;

        UPDATE policy_overrides
        SET org_id = tenant_id
        WHERE org_id IS NULL
          AND tenant_id IS NOT NULL;

        -- Final pass: any row that survived all three chains carries an
        -- organization_id UUID with no matching organizations row AND no
        -- tenant_id. Stamp with a deterministic sentinel so the new policy
        -- can either match or filter it (without leaving the row visible to
        -- nobody). Operators surface these via the 'unresolved-pre-mig110-'
        -- prefix and reconcile out-of-band; not silently dropped.
        UPDATE policy_overrides
        SET org_id = 'unresolved-pre-mig110-' || organization_id::text
        WHERE org_id IS NULL
          AND organization_id IS NOT NULL;

        -- Hard assertion — if anything still NULL, fail the migration
        -- rather than ship a half-converted table.
        SELECT COUNT(*) INTO null_rows FROM policy_overrides WHERE org_id IS NULL;
        IF null_rows > 0 THEN
            RAISE EXCEPTION 'Migration 110: % policy_overrides rows have org_id IS NULL after backfill — manual reconciliation required', null_rows;
        END IF;

        -- Drop BOTH the legacy and the new policy name so re-running the
        -- migration is idempotent (CREATE POLICY has no IF NOT EXISTS).
        DROP POLICY IF EXISTS policy_overrides_tenant_isolation ON policy_overrides;
        DROP POLICY IF EXISTS policy_overrides_org_id_isolation ON policy_overrides;
        CREATE POLICY policy_overrides_org_id_isolation ON policy_overrides
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));

        RAISE NOTICE 'Migration 110: policy_overrides RLS normalized to app.current_org_id';
    ELSE
        RAISE NOTICE 'Migration 110: policy_overrides table not present (community-only); skipping';
    END IF;
END
$$;

-- ============================================================================
-- Step 2: static_policy_versions — switch to org_id via parent subquery
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'static_policy_versions') THEN
        -- DROP BOTH names for re-run idempotency.
        DROP POLICY IF EXISTS static_policy_versions_tenant_isolation ON static_policy_versions;
        DROP POLICY IF EXISTS static_policy_versions_org_id_isolation ON static_policy_versions;
        -- Parent table static_policies has org_id from mig 010. Use it.
        CREATE POLICY static_policy_versions_org_id_isolation ON static_policy_versions
            USING (
                policy_id IN (
                    SELECT id FROM static_policies
                    WHERE org_id = current_setting('app.current_org_id', true)
                       OR tier = 'system'
                )
            );
        RAISE NOTICE 'Migration 110: static_policy_versions RLS normalized to app.current_org_id';
    ELSE
        RAISE NOTICE 'Migration 110: static_policy_versions table not present; skipping';
    END IF;
END
$$;

-- ============================================================================
-- Step 3: policy_versions (mig 022) — RLS USING subquery still queries
-- dynamic_policies on app.tenant_id; once the orchestrator wraps the INSERT
-- inside WithOrgScope (sets app.current_org_id), the subquery evaluates to
-- zero rows under app_role and the INSERT fails 42501. Rekey the subquery
-- to consult dynamic_policies.org_id directly (mig 010 added the column;
-- mig 018 ENABLEd RLS on it).
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'policy_versions') THEN
        DROP POLICY IF EXISTS policy_versions_tenant_isolation ON policy_versions;
        DROP POLICY IF EXISTS policy_versions_org_id_isolation ON policy_versions;
        CREATE POLICY policy_versions_org_id_isolation ON policy_versions
            USING (
                policy_id IN (
                    SELECT policy_id FROM dynamic_policies
                    WHERE org_id = current_setting('app.current_org_id', true)
                )
            );
        RAISE NOTICE 'Migration 110: policy_versions RLS normalized to app.current_org_id';
    ELSE
        RAISE NOTICE 'Migration 110: policy_versions table not present; skipping';
    END IF;
END
$$;

-- ============================================================================
-- Step 4: Smoke verification — no policy on the 3 normalized tables still
-- references the legacy app.tenant_id GUC.
-- ============================================================================
DO $$
DECLARE
    legacy_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO legacy_count
    FROM pg_policies
    WHERE tablename IN ('policy_overrides', 'static_policy_versions', 'policy_versions')
      AND qual LIKE '%app.tenant_id%';
    IF legacy_count > 0 THEN
        RAISE EXCEPTION 'Migration 110: % policies still reference app.tenant_id', legacy_count;
    END IF;
END
$$;

COMMIT;
