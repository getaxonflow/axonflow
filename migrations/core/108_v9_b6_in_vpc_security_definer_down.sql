-- Migration 108 _down: revert in-VPC SECURITY DEFINER + FORCE RLS
--
-- Removes the FORCE RLS hardening (api_keys + customers) and drops the
-- SECURITY DEFINER helpers. The org_id BACKFILL is intentionally NOT
-- reverted — clearing those columns would re-introduce empty-org_id rows
-- that any subsequent re-application of migration 108 would have to
-- backfill again, and clearing them on a deployment that has flipped
-- AXONFLOW_DB_USE_APP_ROLE=true would silently break every authenticated
-- write (WITH CHECK against an empty GUC fails).
--
-- Both api_keys and customers had RLS first-enabled by migration 108. We
-- DISABLE here (mirroring the migration 099 audit_archive down precedent
-- at 099_v9_rls_b1_sparse_tables_down.sql:21-22) so axonflow_app_role
-- (NOBYPASSRLS, mig 098) can still read these tables under the down's
-- expected "rollback to pre-108" semantics. ENABLE-without-policy
-- default-denies for non-table-owner roles per Postgres semantics — under
-- AXONFLOW_DB_USE_APP_ROLE=true (v9.0.0 default), leaving ENABLE on would
-- be an instant auth-lookup outage. The very rollback path the down
-- exists for would trigger the outage it's meant to prevent.
--
-- Idempotent: ALTER TABLE NO FORCE / DISABLE, DROP POLICY IF EXISTS,
-- DROP FUNCTION IF EXISTS — all safe to re-run.

BEGIN;

-- ============================================================================
-- Drop FORCE RLS + policy + DISABLE on customers + api_keys (only if present).
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'customers' AND table_schema = 'public'
    ) THEN
        EXECUTE 'ALTER TABLE customers NO FORCE ROW LEVEL SECURITY';
        EXECUTE 'DROP POLICY IF EXISTS customers_org_id_isolation ON customers';
        EXECUTE 'ALTER TABLE customers DISABLE ROW LEVEL SECURITY';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'api_keys' AND table_schema = 'public'
    ) THEN
        EXECUTE 'ALTER TABLE api_keys NO FORCE ROW LEVEL SECURITY';
        EXECUTE 'DROP POLICY IF EXISTS api_keys_org_isolation ON api_keys';
        EXECUTE 'ALTER TABLE api_keys DISABLE ROW LEVEL SECURITY';
    END IF;
END
$$;

-- ============================================================================
-- Drop the SECURITY DEFINER helpers.
-- ============================================================================
DROP FUNCTION IF EXISTS auth_lookup_api_key(TEXT);
DROP FUNCTION IF EXISTS auth_touch_api_key(VARCHAR);

COMMIT;
