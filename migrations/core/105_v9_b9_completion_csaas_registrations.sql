-- Migration 105: FORCE ROW LEVEL SECURITY on community_saas_registrations
-- + SECURITY DEFINER auth-lookup helper
-- Date: 2026-05-21
--
-- ============================================================================
-- Why this defers from migration 103
-- ============================================================================
-- community_saas_registrations was deliberately excluded from mig 103 because
-- of an auth-bootstrap chicken-and-egg pattern. The credential lookup at
-- `platform/agent/community_saas_register.go::validateCommunityRegistration`
-- runs BEFORE any session/org_id is established — it IS the lookup that
-- resolves which org the request belongs to. Under FORCE RLS with
-- axonflow_app_role, that SELECT returns 0 rows.
--
-- Same shape as `customer_portal_api_keys` (which migration 099 deliberately
-- excluded for the same reason). The fix is the SECURITY DEFINER helper
-- pattern established in migration 104.
--
-- ============================================================================
-- What this migration ships
-- ============================================================================
--   1. csaas_auth_lookup(p_tenant_id) — SECURITY DEFINER helper that bypasses
--      FORCE RLS for the credential-resolution SELECT. Returns ONLY the
--      auth-needed columns (secret_hash, expires_at, disabled_at,
--      terminated_at, org_id), never the full row.
--   2. ENABLE RLS + CREATE POLICY + FORCE on community_saas_registrations.
--   3. REVOKE EXECUTE FROM PUBLIC + GRANT EXECUTE TO axonflow_app_role on
--      the new helper.
--   4. Smoke verification (NOT EXISTS pattern per mig 103).
--
-- ============================================================================
-- What this migration does NOT do (out of scope; see release notes)
-- ============================================================================
--   - Cross-org sweep + recovery-cap sites (community_saas_sweep.go +
--     community_saas_recovery.go) still query community_saas_registrations
--     directly. Under FORCE RLS these break ONCE axonflow_app_role is the
--     connecting role. They need to move to a separate
--     axonflow_platform_admin (BYPASSRLS) connection. Today they connect
--     as the RDS master role (BYPASSRLS), so the FORCE is dormant for
--     them. Mandatory for the v9 app_role flip but not blocking this
--     migration's FORCE rollout.
--
-- ============================================================================
-- Idempotency
-- ============================================================================
-- ALTER TABLE ... ENABLE / FORCE RLS is idempotent.
-- DROP POLICY IF EXISTS + CREATE POLICY is idempotent.
-- CREATE OR REPLACE FUNCTION is idempotent by definition.

BEGIN;

-- ============================================================================
-- csaas_auth_lookup — SECURITY DEFINER pre-auth credential lookup
-- ============================================================================
-- Returns the columns validateCommunityRegistration needs: secret_hash for
-- bcrypt compare, expires_at for TTL check, disabled_at + terminated_at for
-- operator/sweep state checks, org_id so the caller can establish the GUC
-- on subsequent queries.
--
-- STABLE so the planner can elide repeated calls within the same statement.
-- Empty resultset when tenant_id doesn't exist — caller treats as 401.
CREATE OR REPLACE FUNCTION csaas_auth_lookup(p_tenant_id VARCHAR)
    RETURNS TABLE(
        secret_hash    VARCHAR,
        expires_at     TIMESTAMPTZ,
        disabled_at    TIMESTAMPTZ,
        terminated_at  TIMESTAMPTZ,
        org_id         VARCHAR
    )
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT r.secret_hash, r.expires_at, r.disabled_at, r.terminated_at, r.org_id
    FROM community_saas_registrations r
    WHERE r.tenant_id = p_tenant_id;
END;
$$;

COMMENT ON FUNCTION csaas_auth_lookup IS
    'SECURITY DEFINER pre-auth credential lookup for '
    'community_saas_registrations. Bypasses FORCE RLS for the '
    'credential-resolution SELECT in validateCommunityRegistration. '
    'Returns only auth-needed columns + org_id (so caller can set GUC).';

-- ============================================================================
-- Enable + policy on community_saas_registrations
-- ============================================================================
ALTER TABLE community_saas_registrations ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS community_saas_registrations_org_id_isolation
    ON community_saas_registrations;
CREATE POLICY community_saas_registrations_org_id_isolation
    ON community_saas_registrations
    FOR ALL
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

COMMENT ON POLICY community_saas_registrations_org_id_isolation
    ON community_saas_registrations IS
    'Per-org row visibility for axonflow_app_role traffic. Pre-auth lookups '
    'go through csaas_auth_lookup SECURITY DEFINER helper (bypass); '
    'authenticated traffic sees only its own org via SET LOCAL '
    'app.current_org_id.';

-- ============================================================================
-- FORCE — what makes this RLS-enforcing on connections as table owner
-- ============================================================================
ALTER TABLE community_saas_registrations FORCE ROW LEVEL SECURITY;

-- ============================================================================
-- Privilege model: REVOKE PUBLIC + GRANT axonflow_app_role on helper
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE EXECUTE ON FUNCTION csaas_auth_lookup(VARCHAR) FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION csaas_auth_lookup(VARCHAR) TO axonflow_app_role;
        RAISE NOTICE 'Migration 105: granted EXECUTE on csaas_auth_lookup to axonflow_app_role';
    ELSE
        RAISE NOTICE 'Migration 105: axonflow_app_role not present; SECURITY DEFINER helper installed but unbound';
    END IF;
END
$$;

-- ============================================================================
-- Smoke verification — NOT EXISTS pattern per mig 103
-- ============================================================================
DO $$
DECLARE
    r RECORD;
BEGIN
    -- Assert FORCE RLS + ENABLE are on.
    FOR r IN
        SELECT relname, relrowsecurity AS rls_enabled, relforcerowsecurity AS rls_forced
        FROM pg_class
        WHERE relname = 'community_saas_registrations' AND relkind = 'r'
    LOOP
        IF NOT r.rls_enabled THEN
            RAISE EXCEPTION 'Migration 105 failed: RLS not enabled on community_saas_registrations';
        END IF;
        IF NOT r.rls_forced THEN
            RAISE EXCEPTION 'Migration 105 failed: FORCE RLS not active on community_saas_registrations';
        END IF;
        RAISE NOTICE 'Migration 105 verified: community_saas_registrations (rls_enabled=%, rls_forced=%)',
                     r.rls_enabled, r.rls_forced;
    END LOOP;

    -- Assert org_id-isolation policy exists.
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies p
        WHERE p.tablename = 'community_saas_registrations'
          AND p.qual LIKE '%app.current_org_id%'
    ) THEN
        RAISE EXCEPTION 'Migration 105 failed: community_saas_registrations has no app.current_org_id isolation policy';
    END IF;

    -- Assert the SECURITY DEFINER helper exists + is prosecdef=true.
    IF NOT EXISTS (
        SELECT 1 FROM pg_proc
        WHERE proname = 'csaas_auth_lookup'
          AND prosecdef = TRUE
          AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        RAISE EXCEPTION 'Migration 105 failed: csaas_auth_lookup not found or not SECURITY DEFINER';
    END IF;

    RAISE NOTICE 'Migration 105 verified: community_saas_registrations FORCEd + csaas_auth_lookup SECURITY DEFINER';
END
$$;

COMMIT;
