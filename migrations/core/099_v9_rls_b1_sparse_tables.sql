-- Migration 099: FORCE ROW LEVEL SECURITY on sparse audit/config tables
-- Date: 2026-05-20
--
-- This is the FIRST migration in repo history to issue
-- `ALTER TABLE ... FORCE ROW LEVEL SECURITY`. The mechanism is what makes RLS
-- effective in AxonFlow — without FORCE, the RDS master/table owner connection
-- bypasses every policy.
--
-- Tables in this batch:
--   1. deployment_upgrades  — sparse upgrade-history audit; portal-only
--   2. saml_configurations  — sparse SSO config; portal-only, no current callers
--   3. audit_archive        — zero-caller archive; ENABLE+FORCE in this single migration
--
-- All three are touched only by ee/platform/customer-portal/* code paths, whose
-- RLSMiddleware calls SELECT set_org_id($1) on every authenticated request.
-- Agent + orchestrator do not query these three tables.
--
-- Non-breaking under the default master/owner connection: portal middleware
-- already sets app.current_org_id before reaching the handler. FORCE RLS
-- becomes the belt-and-suspenders to the existing WHERE org_id = $1 clauses.

BEGIN;

-- ============================================================================
-- audit_archive — enable RLS + add org_id policy (first-time setup)
-- ============================================================================
-- audit_archive is the only table in this batch without RLS already enabled.
-- Add the standard org_id-isolation policy. The table has zero current callers,
-- so this is purely forward-looking infrastructure.
ALTER TABLE audit_archive ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_archive_org_isolation ON audit_archive;
CREATE POLICY audit_archive_org_isolation ON audit_archive
    FOR ALL
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

COMMENT ON POLICY audit_archive_org_isolation ON audit_archive IS
    'Per-org row visibility. Added in migration 099 alongside FORCE RLS.';

-- ============================================================================
-- deployment_upgrades — ensure RLS + org_id policy exist (idempotent)
-- ============================================================================
-- Migration 019 enabled RLS on deployment_upgrades but only INSIDE a DO block
-- that checked whether organizations table had RLS enabled. That conditional
-- means the deployment_upgrades RLS state is non-deterministic across
-- deployments. We unconditionally ENABLE here so FORCE has something to enforce.
ALTER TABLE deployment_upgrades ENABLE ROW LEVEL SECURITY;

-- The policy may or may not exist (depends on whether migration 019's DO block
-- ran the CREATE POLICY branch). DROP-then-CREATE for determinism.
DROP POLICY IF EXISTS deployment_upgrades_org_isolation ON deployment_upgrades;
CREATE POLICY deployment_upgrades_org_isolation ON deployment_upgrades
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

COMMENT ON POLICY deployment_upgrades_org_isolation ON deployment_upgrades IS
    'Per-org row visibility. Migration 099 hardened the conditional policy '
    'from migration 019.';

-- ============================================================================
-- saml_configurations — ensure RLS + org_id policy exist
-- ============================================================================
-- Migration 018_row_level_security.sql enables RLS on saml_configurations via
-- the DO-loop helper that creates tenant_isolation_{select,insert,update,delete}
-- policies — but those four policies require app.current_org_id to be set or
-- the table effectively becomes invisible. We re-assert here defensively.
ALTER TABLE saml_configurations ENABLE ROW LEVEL SECURITY;

-- 018's four-policy split (one per CRUD verb) is fine — leave them in place.
-- We only need to ensure they exist. If a future migration drops them, this
-- safety policy keeps isolation working.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'saml_configurations'
          AND policyname = 'tenant_isolation_select'
    ) THEN
        CREATE POLICY tenant_isolation_select ON saml_configurations
            FOR SELECT USING (org_id = current_setting('app.current_org_id', true));
        CREATE POLICY tenant_isolation_insert ON saml_configurations
            FOR INSERT WITH CHECK (org_id = current_setting('app.current_org_id', true));
        CREATE POLICY tenant_isolation_update ON saml_configurations
            FOR UPDATE USING (org_id = current_setting('app.current_org_id', true));
        CREATE POLICY tenant_isolation_delete ON saml_configurations
            FOR DELETE USING (org_id = current_setting('app.current_org_id', true));
        RAISE NOTICE 'Created saml_configurations tenant_isolation_* policies (migration 018 had not run)';
    ELSE
        RAISE NOTICE 'saml_configurations tenant_isolation_* policies already exist (idempotent skip)';
    END IF;
END
$$;

-- ============================================================================
-- The point of this migration: FORCE ROW LEVEL SECURITY
-- ============================================================================
-- This is the bit that makes RLS effective for the table owner (RDS master).
-- Until this line runs, an app connection as master sees ALL rows regardless
-- of app.current_org_id.
ALTER TABLE deployment_upgrades FORCE ROW LEVEL SECURITY;
ALTER TABLE saml_configurations FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_archive       FORCE ROW LEVEL SECURITY;

-- ============================================================================
-- Smoke verification
-- ============================================================================
DO $$
DECLARE
    r RECORD;
    bad_count INT := 0;
BEGIN
    FOR r IN
        SELECT relname,
               relrowsecurity AS rls_enabled,
               relforcerowsecurity AS rls_forced
        FROM pg_class
        WHERE relname IN ('deployment_upgrades', 'saml_configurations', 'audit_archive')
        ORDER BY relname
    LOOP
        IF NOT r.rls_enabled THEN
            RAISE EXCEPTION 'Migration 099 failed: RLS not enabled on %', r.relname;
        END IF;
        IF NOT r.rls_forced THEN
            RAISE EXCEPTION 'Migration 099 failed: FORCE RLS not active on %', r.relname;
        END IF;
        RAISE NOTICE 'Migration 099 verified: % (rls_enabled=%, rls_forced=%)',
                     r.relname, r.rls_enabled, r.rls_forced;
    END LOOP;

    -- Verify each table has at least one org_id-based policy.
    FOR r IN
        SELECT tablename, COUNT(*) AS policy_count
        FROM pg_policies
        WHERE tablename IN ('deployment_upgrades', 'saml_configurations', 'audit_archive')
          AND qual LIKE '%app.current_org_id%'
        GROUP BY tablename
    LOOP
        IF r.policy_count < 1 THEN
            RAISE EXCEPTION 'Migration 099 failed: % has no app.current_org_id policy', r.tablename;
        END IF;
        RAISE NOTICE 'Migration 099 verified: % has % org_id-based policies',
                     r.tablename, r.policy_count;
    END LOOP;
END
$$;

COMMIT;
