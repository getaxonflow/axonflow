-- Migration 109: SECURITY DEFINER helpers for pre-auth INSERTs
-- Date: 2026-05-22
--
-- ============================================================================
-- What this migration ships
-- ============================================================================
-- Five SECURITY DEFINER helpers that close the auth-bootstrap chicken-and-egg
-- pattern for write paths where org_id is being MINTED in the same request.
-- These cannot use WithOrgScope at the caller because there's no scope yet —
-- the function itself runs as a BYPASSRLS owner so the INSERT/UPDATE
-- bypasses FORCE RLS atomically.
--
--   1. csaas_register_tenant   — INSERT into community_saas_registrations
--                                (replaces register handler's raw INSERT,
--                                 community_saas_register.go:509,515)
--   2. csaas_register_touch    — UPDATE activity counter on
--                                community_saas_registrations
--                                (replaces register.go:293)
--   3. csaas_recovery_insert   — INSERT recovery-minted row into
--                                community_saas_registrations
--                                (replaces community_saas_recovery.go:472)
--   4. auth_insert_api_key     — INSERT into the in-VPC enterprise api_keys
--                                schema (db_auth.go:458); community-mode safe
--                                because the function body's column refs
--                                resolve at CALL time, not CREATE time —
--                                community DBs lack the operator-managed
--                                api_keys schema so the function is callable
--                                but never called (only generateLicenseKey
--                                calls it, and that code path runs only in
--                                EE mode). Includes p_org_id so the inserted
--                                row is visible to app_role traffic under
--                                mig 108's FORCE RLS policy (raw INSERT
--                                before this migration wrote NULL → row
--                                invisible to any subsequent direct SELECT).
--   5. portal_insert_api_key   — INSERT into customer_portal_api_keys
--                                (customer-portal/api/keys.go:110); same
--                                auth-bootstrap shape since the table stores
--                                the keys used by subsequent auth lookups,
--                                so it is deliberately kept outside FORCE RLS.
--
-- ============================================================================
-- Why SECURITY DEFINER and NOT internal `PERFORM set_config(...)`
-- ============================================================================
-- Two reasons for not setting the GUC inside the function body:
--
--   1. Discriminability under role swap: if the function internally sets
--      app.current_org_id to match the row being inserted, the WITH CHECK
--      predicate passes EVEN under SECURITY INVOKER + axonflow_app_role
--      caller. Relying purely on the owner's BYPASSRLS makes the
--      SECURITY-DEFINER property load-bearing — flipping the function to
--      SECURITY INVOKER causes the INSERT to fail with 42501 instead of
--      silently masking the change.
--
--   2. Established canonical: mig 104 (register_org, register_tenant)
--      + mig 105 (csaas_auth_lookup) + mig 108 (auth_lookup_api_key,
--      auth_touch_api_key) all rely on owner-bypass without internal
--      set_config. This migration follows suit for consistency.
--
-- ============================================================================
-- Why ALTER FUNCTION OWNER TO axonflow_platform_admin
-- ============================================================================
-- SECURITY DEFINER runs as the function's OWNER. By default the owner is
-- whoever ran CREATE FUNCTION (typically RDS master, which is SUPERUSER on
-- AWS RDS — SUPERUSER bypasses RLS unconditionally + has unrestricted DDL).
-- A SUPERUSER-owned SECURITY DEFINER function is a power escalation primitive
-- if its body is ever compromised.
--
-- Pinning ownership to axonflow_platform_admin (BYPASSRLS-but-not-SUPERUSER
-- per mig 098) limits the blast radius: a hostile body change can bypass
-- RLS but cannot perform privileged catalog operations.
--
-- The ALTER is gated on role existence so local-dev installs that haven't
-- run mig 098 still get a working migration (owner stays at the migration
-- runner; CI test runs are under master-owned ownership anyway).
--
-- ============================================================================
-- Idempotency
-- ============================================================================
-- CREATE OR REPLACE FUNCTION is idempotent.
-- ALTER FUNCTION ... OWNER TO is idempotent (no-op if already owned).
-- REVOKE/GRANT is idempotent.
--
-- ============================================================================
-- Depends on
-- ============================================================================
--   068 — community_saas_registrations table
--   088 — client_id column on community_saas_registrations
--   097 — register_tenant (compat sibling)
--   098 — axonflow_app_role + axonflow_platform_admin roles
--   104 — register_org / register_tenant SECURITY DEFINER pattern
--   105 — csaas_auth_lookup pattern (lookup side of csaas-register chicken-egg)
--   108 — auth_lookup_api_key / auth_touch_api_key pattern (lookup+touch
--         side of api_keys chicken-egg; this mig adds the INSERT side)
--   enterprise/100 — customers table (column-checked at function CALL time
--                    for auth_insert_api_key; not a hard CREATE-time dep)
--
-- ============================================================================
-- Out of scope
-- ============================================================================
--   - WithOrgScope wraps where orgID is in-scope at the call site. Those
--     are mechanical wraps, not SECURITY DEFINER candidates.
--   - AdminDB routing hardening for cross-org workers.
--   - mig 018/081 ENABLE-RLS table writers beyond the 5 PRE-AUTH-BARE sites
--     in this migration.

BEGIN;

-- ============================================================================
-- 1. csaas_register_tenant — INSERT into community_saas_registrations
-- ============================================================================
-- Replaces the per-tenant INSERT in community_saas_register.go:509,515.
-- The two register-INSERT variants (with/without claimed_by_email) collapse
-- into a single helper via DEFAULT NULL on the email param + IF branch.
-- The caller's PK-retry-on-unique-violation loop is preserved by re-RAISEing
-- the unique violation from the function — caller's `isUniqueViolation()`
-- check still works.
--
-- org_id is hardcoded to p_tenant_id per migration 100: per-customer
-- org_id = tenant_id = client_id. The caller passes one identifier; the
-- function writes it to all three columns.
CREATE OR REPLACE FUNCTION csaas_register_tenant(
    p_tenant_id      VARCHAR,
    p_secret_hash    VARCHAR,
    p_secret_prefix  VARCHAR,
    p_label          VARCHAR,
    p_expires_at     TIMESTAMPTZ,
    p_email          VARCHAR DEFAULT NULL
) RETURNS VOID
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_email IS NULL THEN
        INSERT INTO community_saas_registrations
            (tenant_id, client_id, secret_hash, secret_prefix, org_id, label, expires_at)
        VALUES
            (p_tenant_id, p_tenant_id, p_secret_hash, p_secret_prefix, p_tenant_id, p_label, p_expires_at);
    ELSE
        INSERT INTO community_saas_registrations
            (tenant_id, client_id, secret_hash, secret_prefix, org_id, label, expires_at, claimed_by_email, claimed_at)
        VALUES
            (p_tenant_id, p_tenant_id, p_secret_hash, p_secret_prefix, p_tenant_id, p_label, p_expires_at, p_email, NOW());
    END IF;
END;
$$;

COMMENT ON FUNCTION csaas_register_tenant(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ, VARCHAR) IS
    'SECURITY DEFINER INSERT into community_saas_registrations for the '
    'per-tenant register path where org_id is being minted in the same '
    'request. Bypasses FORCE RLS via the owning role. PK collisions on '
    'tenant_id are re-RAISEd unchanged so callers can retry with a fresh UUID.';

-- ============================================================================
-- 2. csaas_register_touch — UPDATE activity counter
-- ============================================================================
-- Replaces the fire-and-forget activity UPDATE in
-- community_saas_register.go:293. The activity worker holds its own DB
-- connection from a separate pool — the auth handler's GUC does NOT
-- propagate. SECURITY DEFINER bypasses FORCE RLS via owner.
--
-- Returns rows_affected so the Go caller can detect a no-op (terminated
-- or expired tenant) and log accordingly without an additional SELECT.
CREATE OR REPLACE FUNCTION csaas_register_touch(
    p_tenant_id VARCHAR
) RETURNS INTEGER
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
DECLARE
    v_rows INTEGER;
BEGIN
    UPDATE community_saas_registrations
       SET last_seen_at  = NOW(),
           request_count = request_count + 1
     WHERE tenant_id = p_tenant_id;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END;
$$;

COMMENT ON FUNCTION csaas_register_touch(VARCHAR) IS
    'SECURITY DEFINER UPDATE on community_saas_registrations for the activity '
    'worker. Worker runs on a separate pool/connection — no per-request GUC '
    'propagates from the auth handler, so a direct UPDATE under '
    'axonflow_app_role would match zero rows. Returns rows affected so '
    'callers can log no-ops without an extra SELECT.';

-- ============================================================================
-- 3. csaas_recovery_insert — INSERT recovered tenant row
-- ============================================================================
-- Replaces the recovery-mint INSERT in community_saas_recovery.go:472.
-- Same target table + same FORCE-RLS chicken-egg as csaas_register_tenant.
-- The recovery path ALWAYS carries an email (recovery is email-validated),
-- and the label is always "recovery for <email>" — kept as explicit params
-- so caller doesn't construct the label string inside SQL.
CREATE OR REPLACE FUNCTION csaas_recovery_insert(
    p_tenant_id      VARCHAR,
    p_secret_hash    VARCHAR,
    p_secret_prefix  VARCHAR,
    p_label          VARCHAR,
    p_expires_at     TIMESTAMPTZ,
    p_email          VARCHAR
) RETURNS VOID
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
BEGIN
    INSERT INTO community_saas_registrations
        (tenant_id, client_id, secret_hash, secret_prefix, org_id, label, expires_at, claimed_by_email, claimed_at)
    VALUES
        (p_tenant_id, p_tenant_id, p_secret_hash, p_secret_prefix, p_tenant_id, p_label, p_expires_at, p_email, NOW());
END;
$$;

COMMENT ON FUNCTION csaas_recovery_insert(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ, VARCHAR) IS
    'SECURITY DEFINER INSERT into community_saas_registrations for the '
    'recovery-verify endpoint. Kept distinct from csaas_register_tenant to '
    'preserve drift flexibility — recovery may diverge from register over '
    'time without churning the register helper.';

-- ============================================================================
-- 4. auth_insert_api_key — INSERT into in-VPC enterprise api_keys
-- ============================================================================
-- Replaces the operator-API INSERT in db_auth.go:458 (used by
-- generateLicenseKey when issuing a new API key on an in-VPC enterprise
-- stack). Target table is the operator-managed api_keys schema with
-- customer_id + license_key + license_key_hash columns. Community-mode
-- DBs lack this schema; calls to this function would error at execution
-- with "column does not exist" — but generateLicenseKey is only invoked
-- on the EE binary path so this is theoretical.
--
-- p_org_id is REQUIRED — the row's org_id column is what mig 108's FORCE
-- RLS policy on api_keys keys off (`org_id = current_setting(...)`). The
-- pre-existing raw INSERT omitted the column, so every row landed with
-- org_id=NULL — invisible to direct app_role SELECTs (NULL = anything → NULL,
-- not TRUE). Mig 108's auth_lookup_api_key SECURITY DEFINER masked this in
-- the auth path (the JOIN bypasses RLS), but any direct app_role read fails
-- silently. This helper closes the column-missing gap so defense-in-depth
-- holds even if a future code path SELECTs api_keys directly under app_role.
-- The Go caller already has org_id in scope (loaded from customers earlier
-- in generateLicenseKey at db_auth.go:436-440).
--
-- Returns api_key_id so the Go caller's RETURNING clause migrates 1-for-1.
CREATE OR REPLACE FUNCTION auth_insert_api_key(
    p_customer_id        VARCHAR,
    p_license_key        VARCHAR,
    p_license_key_hash   VARCHAR,
    p_key_name           VARCHAR,
    p_expiry_days        INTEGER,
    p_org_id             VARCHAR
) RETURNS VARCHAR
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
DECLARE
    v_api_key_id VARCHAR;
BEGIN
    INSERT INTO api_keys (
        customer_id,
        license_key,
        license_key_hash,
        key_name,
        key_type,
        expires_at,
        enabled,
        org_id
    ) VALUES (
        p_customer_id,
        p_license_key,
        p_license_key_hash,
        p_key_name,
        'production',
        NOW() + (INTERVAL '1 day' * p_expiry_days),
        true,
        p_org_id
    )
    RETURNING api_key_id::VARCHAR INTO v_api_key_id;
    RETURN v_api_key_id;
END;
$$;

COMMENT ON FUNCTION auth_insert_api_key(VARCHAR, VARCHAR, VARCHAR, VARCHAR, INTEGER, VARCHAR) IS
    'SECURITY DEFINER INSERT into api_keys (in-VPC enterprise auth schema). '
    'Companion to auth_lookup_api_key / auth_touch_api_key — closes the '
    'INSERT side of the chicken-and-egg pattern (org_id is being minted in '
    'the same operator-API request). p_org_id populates the policy-key '
    'column so the row remains visible to direct app_role SELECTs under '
    'FORCE RLS. Community-mode databases lack the operator-managed api_keys '
    'schema — function is installed but never invoked there (caller is EE-only).';

-- ============================================================================
-- 5. portal_insert_api_key — INSERT into customer_portal_api_keys
-- ============================================================================
-- Replaces the authenticated-handler INSERT in
-- ee/platform/customer-portal/api/keys.go:110. session.OrgID is in scope
-- at the call site, so technically a WithOrgScope wrap would work too —
-- but customer_portal_api_keys was deliberately EXCLUDED from FORCE RLS
-- in migration 099 for an auth-bootstrap chicken-and-egg reason: it stores
-- the API keys used by SUBSEQUENT auth lookups. A SECURITY DEFINER helper
-- is the canonical close for this exclusion class (mirrors migration 104).
--
-- Returns id (INTEGER, matching the SERIAL PK on customer_portal_api_keys)
-- so the Go caller's RETURNING migrates 1-for-1. The Go binding uses
-- `var keyID int`.
CREATE OR REPLACE FUNCTION portal_insert_api_key(
    p_org_id     VARCHAR,
    p_key_hash   VARCHAR,
    p_key_prefix VARCHAR,
    p_name       VARCHAR,
    p_scopes     JSONB,
    p_expires_at TIMESTAMPTZ
) RETURNS INTEGER
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
DECLARE
    v_id INTEGER;
BEGIN
    INSERT INTO customer_portal_api_keys
        (org_id, key_hash, key_prefix, name, scopes, expires_at)
    VALUES
        (p_org_id, p_key_hash, p_key_prefix, p_name, p_scopes, p_expires_at)
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

COMMENT ON FUNCTION portal_insert_api_key(VARCHAR, VARCHAR, VARCHAR, VARCHAR, JSONB, TIMESTAMPTZ) IS
    'SECURITY DEFINER INSERT into customer_portal_api_keys. The table stores '
    'the keys used by subsequent portal auth lookups, so it is deliberately '
    'kept outside FORCE RLS to avoid an auth-bootstrap chicken-and-egg; this '
    'helper is the canonical write path so any future FORCE rollout has a '
    'single chokepoint. Returns the generated id.';

-- ============================================================================
-- Owner hardening — pin to axonflow_platform_admin (BYPASSRLS, NOT SUPERUSER)
-- ============================================================================
-- Limits blast radius of any future body change. Idempotent — ALTER FUNCTION
-- OWNER TO is a no-op when the function already has the target owner.
-- Gated on mig 098 having created the role.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        ALTER FUNCTION csaas_register_tenant(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ, VARCHAR) OWNER TO axonflow_platform_admin;
        ALTER FUNCTION csaas_register_touch(VARCHAR)                                                  OWNER TO axonflow_platform_admin;
        ALTER FUNCTION csaas_recovery_insert(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ, VARCHAR) OWNER TO axonflow_platform_admin;
        ALTER FUNCTION auth_insert_api_key(VARCHAR, VARCHAR, VARCHAR, VARCHAR, INTEGER, VARCHAR)                OWNER TO axonflow_platform_admin;
        ALTER FUNCTION portal_insert_api_key(VARCHAR, VARCHAR, VARCHAR, VARCHAR, JSONB, TIMESTAMPTZ)   OWNER TO axonflow_platform_admin;
        RAISE NOTICE 'Migration 109: helpers re-owned to axonflow_platform_admin (BYPASSRLS, non-SUPERUSER)';
    ELSE
        RAISE NOTICE 'Migration 109: axonflow_platform_admin not present (mig 098 not yet run); helpers stay on migration runner owner';
    END IF;
END
$$;

-- ============================================================================
-- Privilege model: REVOKE PUBLIC + GRANT axonflow_app_role
-- ============================================================================
-- REVOKE outside the role probe (always runs — see mig 108 §"Privilege model"
-- for the default-deny rationale). GRANT inside the role probe so local-dev
-- without mig 098 doesn't fail.
REVOKE EXECUTE ON FUNCTION csaas_register_tenant(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ, VARCHAR) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION csaas_register_touch(VARCHAR)                                                  FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION csaas_recovery_insert(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ, VARCHAR) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION auth_insert_api_key(VARCHAR, VARCHAR, VARCHAR, VARCHAR, INTEGER, VARCHAR)                FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION portal_insert_api_key(VARCHAR, VARCHAR, VARCHAR, VARCHAR, JSONB, TIMESTAMPTZ)   FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        GRANT EXECUTE ON FUNCTION csaas_register_tenant(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ, VARCHAR) TO axonflow_app_role;
        GRANT EXECUTE ON FUNCTION csaas_register_touch(VARCHAR)                                                  TO axonflow_app_role;
        GRANT EXECUTE ON FUNCTION csaas_recovery_insert(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ, VARCHAR) TO axonflow_app_role;
        GRANT EXECUTE ON FUNCTION auth_insert_api_key(VARCHAR, VARCHAR, VARCHAR, VARCHAR, INTEGER, VARCHAR)                TO axonflow_app_role;
        GRANT EXECUTE ON FUNCTION portal_insert_api_key(VARCHAR, VARCHAR, VARCHAR, VARCHAR, JSONB, TIMESTAMPTZ)   TO axonflow_app_role;
        RAISE NOTICE 'Migration 109: granted EXECUTE on SECURITY DEFINER helpers to axonflow_app_role';
    ELSE
        RAISE NOTICE 'Migration 109: axonflow_app_role not present (mig 098 not yet run); helpers installed but unbound';
    END IF;
END
$$;

-- ============================================================================
-- Smoke verification — assert all 5 are SECURITY DEFINER + exist
-- ============================================================================
DO $$
DECLARE
    r RECORD;
    expected_funcs TEXT[] := ARRAY[
        'csaas_register_tenant',
        'csaas_register_touch',
        'csaas_recovery_insert',
        'auth_insert_api_key',
        'portal_insert_api_key'
    ];
    fn TEXT;
BEGIN
    -- (1) Assert each function is SECURITY DEFINER (prosecdef=true).
    FOREACH fn IN ARRAY expected_funcs LOOP
        FOR r IN
            SELECT proname, prosecdef
            FROM pg_proc
            WHERE proname = fn
              AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
        LOOP
            IF NOT r.prosecdef THEN
                RAISE EXCEPTION 'Migration 109 failed: function % is NOT SECURITY DEFINER (prosecdef=false)', r.proname;
            END IF;
            RAISE NOTICE 'Migration 109 verified: % is SECURITY DEFINER', r.proname;
        END LOOP;
    END LOOP;

    -- (2) NOT EXISTS pattern — missing function fires the assertion.
    -- (GROUP BY/COUNT silently passes when the set is empty.)
    FOR r IN
        SELECT t.fn AS function_name
        FROM unnest(expected_funcs) AS t(fn)
        WHERE NOT EXISTS (
            SELECT 1 FROM pg_proc p
            WHERE p.proname = t.fn
              AND p.pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
        )
    LOOP
        RAISE EXCEPTION 'Migration 109 failed: function % not found in public schema', r.function_name;
    END LOOP;

    RAISE NOTICE 'Migration 109 verified: all 5 SECURITY DEFINER helpers present';
END
$$;

COMMIT;
