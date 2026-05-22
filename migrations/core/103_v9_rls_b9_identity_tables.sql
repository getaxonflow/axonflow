-- Migration 103: FORCE ROW LEVEL SECURITY on identity tables
-- Date: 2026-05-21
--
-- Migration 099 covered the sparse audit/config trio (deployment_upgrades,
-- saml_configurations, audit_archive). Migrations 101+102 covered the
-- customer-facing audit trio (mcp_query_audits, audit_retention_config,
-- decision_chain). This migration is the v9 cut: identity tables that auth
-- resolution itself reads. Any handler bypass = total auth failure. Last
-- batch by design.
--
-- ============================================================================
-- SCOPE — what this migration FORCES vs. defers
-- ============================================================================
--
-- FORCEd in this migration:
--   1. organizations  — every authenticated portal request lands here through
--                       the RLSMiddleware chain.
--                       Migration 018 already ENABLEs RLS + creates four
--                       tenant_isolation_{select,insert,update,delete}
--                       policies; we re-assert ENABLE + add an explicit
--                       org_id_isolation policy (parity per migration 018),
--                       then FORCE.
--   2. tenants        — uses org_id (NOT NULL since migration 062). Not in
--                       mig 018's array, so we ENABLE + CREATE POLICY +
--                       FORCE.
--
-- DEFERRED from this migration:
--   - community_saas_registrations — auth-bootstrap chicken-and-egg.
--     validateCommunityRegistration in community_saas_register.go
--     SELECTs FROM this table BEFORE the request has a known org_id to
--     SET LOCAL. Same shape as `customer_portal_api_keys`, which migration
--     099 deliberately excluded for the same reason. Needs a SECURITY
--     DEFINER auth-lookup helper (the in-VPC enterprise pattern from
--     migration 108). Closed by migration 105.
--   - sso_configurations — uses `tenant_id` as the isolation key with a
--     policy on `app.tenant_id` (NOT `app.current_org_id`). Needs a paired
--     column rename + policy migration before FORCE can ship with the
--     canonical RLS contract. Closed by migration 106.
--   - saml_configurations — already FORCEd in migration 099. No work.
--
-- ============================================================================
-- DEPLOYMENT BLOCKERS — operators MUST NOT deploy this migration to prod
-- (or to any non-prod env that runs portal traffic) until ALL of these ship:
-- ============================================================================
--
-- 1. **Portal middleware pool-scope fix** —
--    `ee/platform/customer-portal/middleware/rls.go` uses the legacy
--    pool-scope `db.ExecContext(ctx, "SELECT set_org_id($1)", orgID)`
--    pattern on 4 sites. Under FORCE RLS, the GUC set on one pool connection
--    does NOT persist to the handler's subsequent DB calls (which may land
--    on a different connection). Every authenticated portal request lands
--    on one of these identity tables at some point. Without this fix, every
--    portal handler that reads/writes organizations or tenants returns 0
--    rows or WITH CHECK fails.
--
-- 2. **SECURITY DEFINER auth-lookup helpers** —
--    `ee/platform/customer-portal/api/auth.go:174` (`HandleLogin`) and
--    `:58` (`HandleCheckSSOAvailability`) issue
--    `SELECT FROM organizations WHERE org_id = $1` BEFORE the session/org_id
--    is established. Under FORCE RLS this returns 0 rows for every login
--    attempt regardless of credentials. A SECURITY DEFINER PL/pgSQL function
--    that runs as `axonflow_platform_admin` and returns only the auth-needed
--    columns (org_id existence + status + password_hash + name +
--    contact_email) bypasses RLS for the bootstrap query without exposing
--    cross-org data to the calling role. Closed by migration 104.
--
-- 3. **register_tenant() / register_org() / portal_default_tenant_id() must
--    bypass RLS** — `platform/agent/db_auth.go::registerTenantAndOrg` is
--    fire-and-forget after auth and does NOT set app.current_org_id before
--    calling these. Under FORCE RLS, the INSERTs inside register_org /
--    register_tenant silently fail WITH CHECK (logged but non-fatal).
--    portal_default_tenant_id() (mig 065) reads tenants without context and
--    degrades to `org_id` fallback. Convert all three to SECURITY DEFINER,
--    or wrap callers in WithOrgScope. Closed by migration 104.
--
-- Operators reading deploy instructions must NOT trigger
-- deploy-application.yml against any env until all three blockers ship
-- (deploys are workflow_dispatch-only, so this is operator-gated, not
-- CI-gated).
--
-- ============================================================================
-- Why this migration ships before the deploy blockers close:
-- ============================================================================
--
-- Every batch ships:
--   1. The migration file (the rollback unit)
--   2. The handler audit + mutation evidence (forces a complete classification
--      of who reads/writes the FORCEd tables)
--   3. The isolation test pin (contract that the migration must satisfy)
--
-- Shipping (1)+(2)+(3) together forces the design call (auth-bootstrap helper
-- shape) BEFORE any operator can flip FORCE in prod. The contract test
-- (rls_phase6_isolation_test.go) self-applies FORCE in-process so the contract
-- is verifiable today, independent of migration ship status. Once the 3 deploy
-- blockers above clear, the same migration runs and the contract is enforced
-- at the DB layer.
--
-- ============================================================================
-- Idempotency
-- ============================================================================
--
-- ALTER TABLE ... ENABLE / FORCE ROW LEVEL SECURITY are idempotent (re-running
-- on an already-enabled / already-forced table is a no-op).
-- DROP POLICY IF EXISTS + CREATE POLICY pattern is idempotent.

BEGIN;

-- ============================================================================
-- organizations — ENABLE (defensive re-assert) + add org_id_isolation policy
-- + FORCE.
-- ============================================================================
-- Pre-existing state from migration 018: RLS enabled + four
-- tenant_isolation_{select,insert,update,delete} policies whose
-- USING/WITH CHECK expression is `org_id = get_current_org_id()`. That
-- expression is functionally equivalent to our org_id_isolation policy
-- below (`get_current_org_id()` is a STABLE wrapper around
-- `current_setting('app.current_org_id', true)` defined in mig 018:6-13).
--
-- We add a single FOR ALL policy alongside the four FOR-verb policies. Per
-- Postgres semantics, multiple permissive policies are ORed — adding ours
-- is parity, not net-new coverage. We keep migration 018's policies intact
-- so any future drop/recreate at this site doesn't lose isolation.
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS organizations_org_id_isolation ON organizations;
CREATE POLICY organizations_org_id_isolation ON organizations
    FOR ALL
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

COMMENT ON POLICY organizations_org_id_isolation ON organizations IS
    'Per-org row visibility for axonflow_app_role traffic. '
    'Stacks alongside migration 018''s tenant_isolation_* policies (parity).';

-- ============================================================================
-- tenants — ENABLE + CREATE POLICY + FORCE (first-time setup; not in mig 018)
-- ============================================================================
-- tenants.org_id is NOT NULL (mig 062 CREATE TABLE). The register_tenant()
-- function (mig 062, replaced in mig 097) populates org_id on every INSERT.
-- Migration 100 remapped legacy `community-saas` constant rows to
-- per-customer cs_<uuid> values, so every existing tenants row carries a
-- meaningful per-customer org_id today.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenants_org_id_isolation ON tenants;
CREATE POLICY tenants_org_id_isolation ON tenants
    FOR ALL
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

COMMENT ON POLICY tenants_org_id_isolation ON tenants IS
    'Per-org row visibility. tenants.org_id is NOT NULL (mig 062) and '
    'mig 100 ensures per-customer org_id values for the cs_* cohort.';

-- ============================================================================
-- The point of this migration: FORCE ROW LEVEL SECURITY
-- ============================================================================
-- Until this line runs, an app connection as the table owner (RDS master)
-- sees ALL rows regardless of app.current_org_id. This is what protects
-- against handler bugs that forget to call SET LOCAL.
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE tenants       FORCE ROW LEVEL SECURITY;

-- ============================================================================
-- Smoke verification — uses NOT EXISTS pattern so missing-policy rows fire
-- the assertion (the GROUP BY pattern in mig 099/101 silently skipped tables
-- with zero matching policies because GROUP BY excludes them entirely).
-- ============================================================================
DO $$
DECLARE
    r RECORD;
    expected_tables TEXT[] := ARRAY['organizations', 'tenants'];
    tbl TEXT;
BEGIN
    -- Assert FORCE RLS + ENABLE are on for both tables.
    FOREACH tbl IN ARRAY expected_tables LOOP
        FOR r IN
            SELECT relname,
                   relrowsecurity AS rls_enabled,
                   relforcerowsecurity AS rls_forced
            FROM pg_class
            WHERE relname = tbl
              AND relkind = 'r'
        LOOP
            IF NOT r.rls_enabled THEN
                RAISE EXCEPTION 'Migration 103 failed: RLS not enabled on %', r.relname;
            END IF;
            IF NOT r.rls_forced THEN
                RAISE EXCEPTION 'Migration 103 failed: FORCE RLS not active on %', r.relname;
            END IF;
            RAISE NOTICE 'Migration 103 verified: % (rls_enabled=%, rls_forced=%)',
                         r.relname, r.rls_enabled, r.rls_forced;
        END LOOP;
    END LOOP;

    -- Assert each identity table has at least one org_id-isolation policy. The
    -- predicate accepts either the literal `app.current_org_id` pattern
    -- (this migration's policies) OR the `get_current_org_id()` wrapper
    -- pattern (migration 018's `tenant_isolation_*` policies on
    -- organizations). Both expand to the same GUC at runtime; widening the
    -- predicate prevents the smoke from spuriously failing if some future
    -- migration drops THIS migration's policy while leaving 018's intact.
    --
    -- NOT EXISTS pattern: this loop fires for tables with ZERO matching
    -- policies. The GROUP BY/COUNT pattern in migs 099/101 silently
    -- skipped tables with zero matches (GROUP BY excludes them).
    FOR r IN
        SELECT t.tbl AS table_name
        FROM unnest(expected_tables) AS t(tbl)
        WHERE NOT EXISTS (
            SELECT 1 FROM pg_policies p
            WHERE p.tablename = t.tbl
              AND (p.qual LIKE '%app.current_org_id%' OR p.qual LIKE '%get_current_org_id()%')
        )
    LOOP
        RAISE EXCEPTION 'Migration 103 failed: % has no org_id isolation policy (neither app.current_org_id nor get_current_org_id())', r.table_name;
    END LOOP;

    -- Positive-side log: count how many org_id-isolation policies each
    -- table has (same widened predicate). Informational only — actual
    -- failure path is the NOT EXISTS loop above.
    FOR r IN
        SELECT p.tablename, COUNT(*) AS policy_count
        FROM pg_policies p
        WHERE p.tablename = ANY(expected_tables)
          AND (p.qual LIKE '%app.current_org_id%' OR p.qual LIKE '%get_current_org_id()%')
        GROUP BY p.tablename
        ORDER BY p.tablename
    LOOP
        RAISE NOTICE 'Migration 103 verified: % has % org_id-isolation policies',
                     r.tablename, r.policy_count;
    END LOOP;
END
$$;

COMMIT;
