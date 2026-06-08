-- Migration 118: SECURITY DEFINER helper for portal session lookup
-- Date: 2026-06-08
--
-- Closes a latent bug that surfaces the moment AXONFLOW_DB_USE_APP_ROLE=true
-- is enabled (prod app-role flip, #2380): the portal AuthMiddleware
-- (ee/platform/customer-portal/middleware/dev_auth.go) reads `user_sessions`
-- by session_id BEFORE any org context can be established — it is the lookup
-- that DISCOVERS which org the session belongs to, so there is no
-- app.current_org_id to SET LOCAL beforehand.
--
-- `user_sessions` has RLS enabled with the org-scoped tenant_isolation_select
-- policy (org_id = get_current_org_id(), migration 018). Today the portal
-- connects as the Postgres superuser `axonflow` (BYPASSRLS) with
-- AXONFLOW_DB_USE_APP_ROLE=false, so the unscoped SELECT works. Under the
-- axonflow_app_role (NOBYPASSRLS, subject to RLS) the policy evaluates
-- get_current_org_id() = '' → 0 rows → every authenticated portal request
-- 401s ("Unauthorized - invalid session"). Verified empirically: a NOBYPASSRLS
-- role + FORCE RLS sees 0 rows for a known-good session_id.
--
-- This is the same class of pre-auth lookup that migration 104 solved for the
-- HandleLogin org-credential read. We follow that pattern exactly: a
-- SECURITY DEFINER function (runs as its owner, which has BYPASSRLS) that
-- returns only the session columns the middleware needs.
--
-- ============================================================================
-- portal_session_lookup — pre-auth session resolution by session_id
-- ============================================================================
-- Returns the session row for a given session_id, bypassing RLS on
-- user_sessions. Returns an empty resultset (NOT a NULL row) when the
-- session_id does not exist — the caller treats no-row as "invalid session".
-- Exposes only the columns AuthMiddleware needs; never the full table.
--
-- STABLE so the planner can elide repeated calls within a statement.

BEGIN;

-- DROP before CREATE: a plain CREATE OR REPLACE cannot change a function's
-- return type, so dropping first keeps this migration safely re-runnable even
-- if an earlier definition with a different RETURNS TABLE shape exists.
DROP FUNCTION IF EXISTS portal_session_lookup(VARCHAR);

CREATE OR REPLACE FUNCTION portal_session_lookup(p_session_id VARCHAR)
    -- Column types MUST match user_sessions exactly (RETURN QUERY enforces a
    -- structural type check): org_id/tenant_id/user_email/user_name are
    -- VARCHAR(255); expires_at is TIMESTAMP WITHOUT TIME ZONE.
    RETURNS TABLE(
        org_id     VARCHAR,
        tenant_id  VARCHAR,
        user_email VARCHAR,
        user_name  VARCHAR,
        expires_at TIMESTAMP
    )
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT s.org_id, s.tenant_id, s.user_email, s.user_name, s.expires_at
    FROM user_sessions s
    WHERE s.session_id = p_session_id;
END;
$$;

COMMENT ON FUNCTION portal_session_lookup IS
    'SECURITY DEFINER pre-auth session lookup. Bypasses RLS on user_sessions '
    'for the AuthMiddleware session-resolution path, which runs before any '
    'org GUC can be set (the lookup is what establishes the org). Returns '
    'only the columns the middleware needs, never the full row. See mig 104 '
    'for the equivalent HandleLogin org-credential helper.';

-- ============================================================================
-- Privilege model: REVOKE PUBLIC + GRANT axonflow_app_role
-- ============================================================================
-- Mirror migration 104: REVOKE EXECUTE FROM PUBLIC so only explicitly granted
-- roles can call it; GRANT to axonflow_app_role so the request-path portal
-- connection can invoke it. The role probe guards local-dev installs that
-- haven't provisioned axonflow_app_role (mig 098).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE EXECUTE ON FUNCTION portal_session_lookup(VARCHAR) FROM PUBLIC;
        GRANT  EXECUTE ON FUNCTION portal_session_lookup(VARCHAR) TO axonflow_app_role;
        RAISE NOTICE 'Migration 118: granted EXECUTE on portal_session_lookup to axonflow_app_role';
    ELSE
        RAISE NOTICE 'Migration 118: axonflow_app_role not present (mig 098 not yet run); portal_session_lookup installed but unbound';
    END IF;
END
$$;

-- ============================================================================
-- Smoke verification — assert the function is SECURITY DEFINER
-- ============================================================================
-- prosecdef=true means SECURITY DEFINER per pg_proc. Fail the migration if the
-- helper landed without the SECURITY DEFINER attribute (mirrors mig 104).
DO $$
DECLARE
    r RECORD;
BEGIN
    SELECT proname, prosecdef INTO r
    FROM pg_proc
    WHERE proname = 'portal_session_lookup'
      AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Migration 118 failed: portal_session_lookup not created';
    END IF;
    IF NOT r.prosecdef THEN
        RAISE EXCEPTION 'Migration 118 failed: portal_session_lookup is NOT SECURITY DEFINER (prosecdef=false)';
    END IF;
    RAISE NOTICE 'Migration 118 verified: portal_session_lookup is SECURITY DEFINER';
END
$$;

COMMIT;
