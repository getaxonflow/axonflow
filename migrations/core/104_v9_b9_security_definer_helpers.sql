-- Migration 104: SECURITY DEFINER auth helpers for SaaS portal
-- Date: 2026-05-21
--
-- Gates the AXONFLOW_DB_USE_APP_ROLE=true flip by ensuring every pre-auth
-- lookup + fire-and-forget register function continues to work when the
-- connecting role is axonflow_app_role (NOBYPASSRLS, subject to FORCE RLS
-- on organizations + tenants via mig 103).
--
-- ============================================================================
-- Why SECURITY DEFINER and not "wrap caller in SET LOCAL"
-- ============================================================================
-- Three call sites cannot use the canonical withOrgScope pattern:
--
--   1. ee/platform/customer-portal/api/auth.go::HandleLogin (line ~174)
--      issues `SELECT password_hash, name, contact_email FROM organizations
--      WHERE org_id = $1` BEFORE any session/org_id is established. The
--      whole point of this query is to find out WHICH org the caller
--      claims to be. There is no `current_org_id` to SET LOCAL at this
--      point — it is the lookup that establishes it.
--
--   2. ee/platform/customer-portal/api/auth.go::HandleCheckSSOAvailability
--      (line ~58 + ~86) issues two pre-auth lookups against organizations
--      (existence + status) and sso_configurations (SSO config row). Same
--      shape: no session yet.
--
--   3. platform/agent/db_auth.go::registerTenantAndOrg (line ~547) is
--      called as a fire-and-forget goroutine AFTER auth succeeds, but it
--      runs on a fresh DB conn that does NOT carry the auth-handler's
--      transactional GUC. It invokes `SELECT register_org($1, $2, $3, $4)`
--      and `SELECT register_tenant($1, $2)` without first issuing
--      SET LOCAL app.current_org_id, so the INSERTs inside register_org()
--      (organizations) and register_tenant() (tenants) silently fail
--      WITH CHECK once FORCE RLS is active.
--
-- SECURITY DEFINER functions run as the function's OWNER (the role that
-- created them — typically the table owner / RDS master), which has
-- BYPASSRLS. The callers (axonflow_app_role) only see the function's
-- declared return columns, not the underlying table. The same pattern is
-- mirrored on the in-VPC enterprise auth path in migration 108.
--
-- ============================================================================
-- Functions added/redefined
-- ============================================================================
--   portal_auth_lookup_org(p_org_id)       — NEW, replaces auth.go:174 SELECT
--   portal_check_sso_availability(p_org_id)— NEW, replaces auth.go:58+86 reads
--   portal_default_tenant_id(p_org_id)     — converted to SECURITY DEFINER
--   register_org(...)                       — converted to SECURITY DEFINER
--   register_tenant(...)                    — converted to SECURITY DEFINER
--
-- All five functions have EXECUTE REVOKEd from PUBLIC and GRANTed only to
-- axonflow_app_role. Privilege chain: app_role can call → function bypasses
-- RLS as owner → app_role caller sees only declared columns.
--
-- ============================================================================
-- Idempotency
-- ============================================================================
-- CREATE OR REPLACE FUNCTION is idempotent. The REVOKE/GRANT block is
-- guarded by DO blocks that probe pg_roles for axonflow_app_role existence
-- so the migration also works on local-dev databases that haven't run
-- migration 098 yet.

BEGIN;

-- ============================================================================
-- portal_auth_lookup_org — pre-auth org existence + password/name lookup
-- ============================================================================
-- Returns auth-needed columns ONLY. Does NOT expose the full organizations
-- row. STABLE so query planner can elide repeated calls within the same
-- statement.
--
-- Returns empty resultset (NOT NULL row) if the org doesn't exist or is not
-- ACTIVE — caller treats no-row as "Invalid credentials" (timing-folded
-- with bad-password per auth.go's existing comment block at line ~190).
CREATE OR REPLACE FUNCTION portal_auth_lookup_org(p_org_id VARCHAR)
    RETURNS TABLE(
        password_hash VARCHAR,
        name          VARCHAR,
        contact_email VARCHAR
    )
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT o.password_hash, o.name, o.contact_email
    FROM organizations o
    WHERE o.org_id = p_org_id
      AND o.status = 'ACTIVE';
END;
$$;

COMMENT ON FUNCTION portal_auth_lookup_org IS
    'SECURITY DEFINER pre-auth lookup. Bypasses FORCE RLS on organizations '
    'for the credential-resolution path in HandleLogin. Returns only '
    'auth-needed columns, never the full row.';

-- ============================================================================
-- portal_check_sso_availability — pre-auth SSO config lookup
-- ============================================================================
-- HandleCheckSSOAvailability needs two facts before auth: (1) does the
-- org exist + is it ACTIVE; (2) is SSO configured for it (provider,
-- enabled, enforce_sso). We fold both into one function to minimize
-- round trips AND so the function returns a single deterministic shape.
--
-- org_exists = false → caller responds {sso_enabled:false} per
-- HandleCheckSSOAvailability's existing "Don't reveal whether org exists"
-- contract. provider/enabled/enforce_sso NULL/false in that case.
--
-- The underlying sso_configurations table uses tenant_id as its key
-- with the value of org_id (the type confusion documented in
-- auth.go:78-82). This SECURITY DEFINER helper preserves the existing
-- semantics — passing p_org_id straight into the tenant_id filter — so
-- the call site rewrite is a one-line swap. Migration 106 adds an
-- org_id column to sso_configurations and updates this function body
-- to use it.
CREATE OR REPLACE FUNCTION portal_check_sso_availability(p_org_id VARCHAR)
    RETURNS TABLE(
        org_exists  BOOLEAN,
        provider    VARCHAR,
        enabled     BOOLEAN,
        enforce_sso BOOLEAN
    )
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
DECLARE
    v_exists BOOLEAN;
BEGIN
    SELECT EXISTS(
        SELECT 1 FROM organizations
        WHERE org_id = p_org_id AND status = 'ACTIVE'
    ) INTO v_exists;

    IF NOT v_exists THEN
        RETURN QUERY SELECT FALSE, NULL::VARCHAR, FALSE, FALSE;
        RETURN;
    END IF;

    -- Org exists. Probe sso_configurations. If no row, return existence=true
    -- with NULL provider so caller treats it as "no SSO configured".
    RETURN QUERY
    SELECT TRUE, s.provider, s.enabled, s.enforce_sso
    FROM sso_configurations s
    WHERE s.tenant_id = p_org_id
    LIMIT 1;

    -- If the SELECT returned zero rows, the caller still needs the
    -- existence=true signal. Emit it.
    IF NOT FOUND THEN
        RETURN QUERY SELECT TRUE, NULL::VARCHAR, FALSE, FALSE;
    END IF;
END;
$$;

COMMENT ON FUNCTION portal_check_sso_availability IS
    'SECURITY DEFINER pre-auth SSO probe. Bypasses FORCE RLS on '
    'organizations + sso_configurations for the pre-login SSO-availability '
    'check.';

-- ============================================================================
-- portal_default_tenant_id — convert to SECURITY DEFINER
-- ============================================================================
-- Existing function from migration 065 reads `tenants` to resolve the
-- canonical tenant for an org. Called from auth.go::HandleLogin OUTSIDE
-- the user_sessions INSERT txn (so the GUC is unset at call time).
-- Under FORCE RLS on tenants (migration 103) this returned NULL,
-- forcing the fallback path that aliases tenant_id := org_id.
--
-- Converting to SECURITY DEFINER restores the canonical tenant resolution.
-- Same signature as mig 065; body unchanged; STABLE preserved.
CREATE OR REPLACE FUNCTION portal_default_tenant_id(p_org_id VARCHAR(255))
    RETURNS VARCHAR(255)
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
DECLARE
    result VARCHAR(255);
BEGIN
    -- Prefer the tenant with the same tenant_id as org_id (canonical default)
    SELECT tenant_id INTO result
    FROM tenants
    WHERE org_id = p_org_id AND tenant_id = p_org_id
    LIMIT 1;

    IF result IS NOT NULL THEN
        RETURN result;
    END IF;

    -- Otherwise return the oldest tenant for this org
    SELECT tenant_id INTO result
    FROM tenants
    WHERE org_id = p_org_id
    ORDER BY created_at ASC
    LIMIT 1;

    -- Fall back to org_id if no tenants exist at all
    IF result IS NULL THEN
        result := p_org_id;
    END IF;

    RETURN result;
END;
$$;

COMMENT ON FUNCTION portal_default_tenant_id IS
    'SECURITY DEFINER variant of the mig 065 helper. Bypasses FORCE RLS '
    'on tenants for the post-auth tenant resolution called outside the '
    'user_sessions INSERT txn.';

-- ============================================================================
-- register_org — convert to SECURITY DEFINER
-- ============================================================================
-- Existing function from migration 062 does INSERT ... ON CONFLICT UPDATE
-- against `organizations`. Called fire-and-forget from
-- platform/agent/db_auth.go::registerTenantAndOrg WITHOUT a SET LOCAL.
-- Under FORCE RLS on organizations (migration 103) the INSERT path
-- silently fails WITH CHECK. SECURITY DEFINER restores the upsert.
--
-- Body unchanged from migration 062.
CREATE OR REPLACE FUNCTION register_org(
    p_org_id VARCHAR(255),
    p_name VARCHAR(255) DEFAULT NULL,
    p_tier VARCHAR(50) DEFAULT 'Community',
    p_max_nodes INTEGER DEFAULT 2
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    -- Only if organizations table exists
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'organizations'
    ) THEN
        INSERT INTO organizations (org_id, name, tier, max_nodes, license_key)
        VALUES (p_org_id, COALESCE(p_name, p_org_id), p_tier, p_max_nodes, '')
        ON CONFLICT (org_id) DO UPDATE SET
            tier = EXCLUDED.tier,
            max_nodes = EXCLUDED.max_nodes,
            updated_at = CURRENT_TIMESTAMP
        WHERE organizations.tier != EXCLUDED.tier
           OR organizations.max_nodes != EXCLUDED.max_nodes;
    END IF;
END;
$$;

COMMENT ON FUNCTION register_org IS
    'SECURITY DEFINER variant of the mig 062 register_org. Bypasses FORCE '
    'RLS on organizations for fire-and-forget auto-registration from '
    'registerTenantAndOrg.';

-- ============================================================================
-- register_tenant — convert to SECURITY DEFINER (body from mig 097)
-- ============================================================================
-- Migration 097 widened register_tenant to also write client_id. We keep
-- that body intact and add SECURITY DEFINER + search_path lock.
CREATE OR REPLACE FUNCTION register_tenant(
    p_tenant_id VARCHAR(255),
    p_org_id VARCHAR(255),
    p_name VARCHAR(255) DEFAULT NULL
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    -- v9 compat: client_id mirrors tenant_id during the v9 compatibility window.
    INSERT INTO tenants (tenant_id, client_id, org_id, name)
    VALUES (p_tenant_id, p_tenant_id, p_org_id, COALESCE(p_name, p_tenant_id))
    ON CONFLICT (tenant_id) DO NOTHING;
END;
$$;

COMMENT ON FUNCTION register_tenant IS
    'SECURITY DEFINER variant of the mig 097 register_tenant. Bypasses '
    'FORCE RLS on tenants for fire-and-forget auto-registration from '
    'registerTenantAndOrg.';

-- ============================================================================
-- Privilege model: REVOKE PUBLIC + GRANT axonflow_app_role
-- ============================================================================
-- All five SECURITY DEFINER functions: REVOKE EXECUTE FROM PUBLIC so the
-- only callers are roles explicitly granted EXECUTE. GRANT to
-- axonflow_app_role so request-path callers can invoke them.
--
-- The role probe guards local-dev installs that haven't run mig 098.
-- On RDS prod, mig 098 always runs before 104 so the role is present.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE EXECUTE ON FUNCTION portal_auth_lookup_org(VARCHAR)           FROM PUBLIC;
        REVOKE EXECUTE ON FUNCTION portal_check_sso_availability(VARCHAR)    FROM PUBLIC;
        REVOKE EXECUTE ON FUNCTION portal_default_tenant_id(VARCHAR)         FROM PUBLIC;
        REVOKE EXECUTE ON FUNCTION register_org(VARCHAR, VARCHAR, VARCHAR, INTEGER)         FROM PUBLIC;
        REVOKE EXECUTE ON FUNCTION register_tenant(VARCHAR, VARCHAR, VARCHAR)               FROM PUBLIC;

        GRANT EXECUTE ON FUNCTION portal_auth_lookup_org(VARCHAR)           TO axonflow_app_role;
        GRANT EXECUTE ON FUNCTION portal_check_sso_availability(VARCHAR)    TO axonflow_app_role;
        GRANT EXECUTE ON FUNCTION portal_default_tenant_id(VARCHAR)         TO axonflow_app_role;
        GRANT EXECUTE ON FUNCTION register_org(VARCHAR, VARCHAR, VARCHAR, INTEGER)         TO axonflow_app_role;
        GRANT EXECUTE ON FUNCTION register_tenant(VARCHAR, VARCHAR, VARCHAR)               TO axonflow_app_role;

        RAISE NOTICE 'Migration 104: granted EXECUTE on SECURITY DEFINER helpers to axonflow_app_role';
    ELSE
        RAISE NOTICE 'Migration 104: axonflow_app_role not present (mig 098 not yet run on this DB); SECURITY DEFINER helpers still installed but unbound';
    END IF;
END
$$;

-- ============================================================================
-- Smoke verification — assert all 5 functions are SECURITY DEFINER
-- ============================================================================
-- prosecdef=true means SECURITY DEFINER per pg_proc. NOT EXISTS pattern
-- (per mig 103) so missing functions fire the assertion.
DO $$
DECLARE
    r RECORD;
    expected_funcs TEXT[] := ARRAY[
        'portal_auth_lookup_org',
        'portal_check_sso_availability',
        'portal_default_tenant_id',
        'register_org',
        'register_tenant'
    ];
    fn TEXT;
BEGIN
    FOREACH fn IN ARRAY expected_funcs LOOP
        FOR r IN
            SELECT proname, prosecdef
            FROM pg_proc
            WHERE proname = fn
              AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
        LOOP
            IF NOT r.prosecdef THEN
                RAISE EXCEPTION 'Migration 104 failed: function % is NOT SECURITY DEFINER (prosecdef=false)', r.proname;
            END IF;
            RAISE NOTICE 'Migration 104 verified: % is SECURITY DEFINER', r.proname;
        END LOOP;
    END LOOP;

    -- Assert each expected function exists. NOT EXISTS so missing functions
    -- fire the assertion (the FOREACH-FOR loop above silently skips
    -- non-matching rows).
    FOR r IN
        SELECT t.fn AS function_name
        FROM unnest(expected_funcs) AS t(fn)
        WHERE NOT EXISTS (
            SELECT 1 FROM pg_proc p
            WHERE p.proname = t.fn
              AND p.pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
        )
    LOOP
        RAISE EXCEPTION 'Migration 104 failed: function % not found in public schema', r.function_name;
    END LOOP;
END
$$;

COMMIT;
