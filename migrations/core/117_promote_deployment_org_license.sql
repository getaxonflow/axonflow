-- Migration 117: promote_deployment_org_license — RLS-safe license-tier promotion
-- Date: 2026-06-07
-- Depends: 002_organizations_and_auth
--
-- ============================================================================
-- Why this exists (#2535)
-- ============================================================================
-- The agent parses the deployment's Enterprise license at boot and stores the
-- tier IN-MEMORY only (run.go: licenseTier.Store(result.Tier), surfaced at
-- /health). Nothing ever writes the licensed tier into the DB. The portal,
-- node-limit enforcement, and compliance-evidence paths all read the licensed
-- tier from organizations.tier — which migration 094 seeds as 'Community'
-- (max_nodes=2) with ON CONFLICT (org_id) DO NOTHING and never promotes.
--
-- Result: a valid Enterprise license deploys, /health reports Enterprise, but
-- the portal UI (and every other DB consumer) reads 'Community'.
--
-- The durable fix is for the agent to upsert the deployment org's
-- organizations row to the licensed tier after license validation. This
-- migration supplies the RLS-safe write primitive that call site uses.
--
-- ============================================================================
-- Why a NEW helper and not register_org (mig 104:226)
-- ============================================================================
-- register_org(org, name, tier, max_nodes) is the existing SECURITY DEFINER
-- upsert helper with the exact ON CONFLICT DO UPDATE shape this fix needs.
-- We deliberately do NOT reuse it directly for two reasons:
--
--   1. register_org has no expires_at parameter. The portal reads
--      organizations.expires_at (customer-portal/api/license.go:61) to derive
--      ACTIVE / EXPIRING_SOON / EXPIRED status. The licensed expiry must land
--      in the row, so the promotion helper has to carry expires_at — which
--      register_org structurally cannot.
--
--   2. register_org's 4-arg signature is a stable contract invoked elsewhere
--      (platform/agent/db_auth.go::registerTenantAndOrg fire-and-forget).
--      Adding an optional 5th param would create an ambiguous-overload call
--      against the existing 4-arg invocations; replacing the signature would
--      break that caller. A separate, purpose-named helper avoids both.
--
-- promote_deployment_org_license mirrors register_org's RLS-safety model
-- EXACTLY (SECURITY DEFINER, search_path lock, REVOKE PUBLIC + GRANT
-- app_role, IF-EXISTS table guard, ON CONFLICT DO UPDATE ... WHERE distinct)
-- and extends it with expires_at. It is NOT a raw RLS-bypassing INSERT in Go:
-- the agent calls it as `SELECT promote_deployment_org_license(...)`, so the
-- write executes as the function OWNER — the migration/table-owning role,
-- which bypasses FORCE RLS on organizations (mig 103) — rather than under
-- axonflow_app_role (NOBYPASSRLS), which mig 103 would reject. Same posture
-- as register_org (mig 104).
--
-- ============================================================================
-- Idempotency
-- ============================================================================
-- CREATE OR REPLACE FUNCTION is idempotent. The function body is
-- INSERT ... ON CONFLICT (org_id) DO UPDATE ... WHERE (tier|max_nodes|
-- expires_at) IS DISTINCT FROM EXCLUDED — so a second boot with the same
-- license is a guaranteed no-op (the WHERE matches no rows once the row
-- already holds the licensed values; no error, no flapping). IS DISTINCT FROM
-- (not !=) is used so a NULL expires_at compares correctly. The REVOKE/GRANT
-- block is guarded by a pg_roles probe so the migration also works on
-- local-dev databases that haven't run migration 098 yet.

BEGIN;

-- ============================================================================
-- promote_deployment_org_license — upsert the deployment org to its licensed
-- tier / node cap / expiry
-- ============================================================================
-- Promotes the migration-094 'Community' placeholder row IN PLACE (ON CONFLICT
-- DO UPDATE) when one exists, or inserts a fresh row (license_key='' mirrors
-- the 094 seed; name defaults to org_id) when it does not. license_key is left
-- untouched on UPDATE — it is not the tier source of truth and the seed/login
-- paths own it.
CREATE OR REPLACE FUNCTION promote_deployment_org_license(
    p_org_id     VARCHAR(255),
    p_tier       VARCHAR(50),
    p_max_nodes  INTEGER,
    p_expires_at TIMESTAMP DEFAULT NULL
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    -- Only if organizations table exists (mirrors register_org's guard so
    -- the helper is safe to install on schemas where 002 hasn't run).
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'organizations'
    ) THEN
        INSERT INTO organizations (org_id, name, tier, max_nodes, license_key, expires_at)
        VALUES (p_org_id, p_org_id, p_tier, p_max_nodes, '', p_expires_at)
        ON CONFLICT (org_id) DO UPDATE SET
            tier       = EXCLUDED.tier,
            max_nodes  = EXCLUDED.max_nodes,
            expires_at = EXCLUDED.expires_at,
            updated_at = CURRENT_TIMESTAMP
        WHERE organizations.tier       IS DISTINCT FROM EXCLUDED.tier
           OR organizations.max_nodes  IS DISTINCT FROM EXCLUDED.max_nodes
           OR organizations.expires_at IS DISTINCT FROM EXCLUDED.expires_at;
    END IF;
END;
$$;

COMMENT ON FUNCTION promote_deployment_org_license IS
    'SECURITY DEFINER upsert that promotes the deployment org''s organizations '
    'row to its licensed tier/max_nodes/expires_at. Bypasses FORCE RLS on '
    'organizations (mig 103) for the agent boot-time license-tier sync (#2535). '
    'Mirrors register_org (mig 104) with an added expires_at column.';

-- ============================================================================
-- Privilege model: REVOKE PUBLIC + GRANT axonflow_app_role
-- ============================================================================
-- Same posture as the mig-104 helpers. The agent's migration connection is
-- typically the table owner (which can always EXECUTE its own functions); the
-- GRANT covers deployments where the boot connection runs as
-- axonflow_app_role. The role probe guards local-dev installs that haven't
-- run mig 098.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE EXECUTE ON FUNCTION promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMP) FROM PUBLIC;
        GRANT  EXECUTE ON FUNCTION promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMP) TO axonflow_app_role;
        RAISE NOTICE 'Migration 117: granted EXECUTE on promote_deployment_org_license to axonflow_app_role';
    ELSE
        RAISE NOTICE 'Migration 117: axonflow_app_role not present (mig 098 not yet run on this DB); promote_deployment_org_license installed but unbound';
    END IF;
END
$$;

-- ============================================================================
-- Smoke verification — assert the function exists and is SECURITY DEFINER
-- ============================================================================
DO $$
DECLARE
    v_secdef BOOLEAN;
BEGIN
    SELECT prosecdef INTO v_secdef
    FROM pg_proc
    WHERE proname = 'promote_deployment_org_license'
      AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');

    IF v_secdef IS NULL THEN
        RAISE EXCEPTION 'Migration 117 failed: promote_deployment_org_license not found in public schema';
    END IF;
    IF NOT v_secdef THEN
        RAISE EXCEPTION 'Migration 117 failed: promote_deployment_org_license is NOT SECURITY DEFINER (prosecdef=false)';
    END IF;
    RAISE NOTICE 'Migration 117 verified: promote_deployment_org_license is SECURITY DEFINER';
END
$$;

COMMIT;
