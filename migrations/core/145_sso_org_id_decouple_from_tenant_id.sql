-- Migration 145: sso_* org_id must hold a REAL org, never the '__platform__'
--                sentinel (#2960, epic #2919)
-- Date: 2026-07-17
-- Purpose: sso_configurations carries TWO distinct keys that were conflated:
--
--   * tenant_id — the SSO ADDRESSING key: which config to load. In-VPC
--     collapses it to the literal '__platform__' (customer-portal
--     getSSOTenantID) so one config serves the whole deployment, and the
--     SAML ACS/login URL (/auth/saml/__platform__/...) is built from it.
--     This collapse is intentional and is PRESERVED.
--
--   * org_id — the RLS ISOLATION key: mig 106's FORCE RLS policy
--     (org_id = current_setting('app.current_org_id')). It is a security
--     boundary and must always name a real org.
--
-- The portal INSERT bound the same value to both columns (VALUES ($1, $1, ...)),
-- so in in-vpc the sentinel landed in org_id too. Every reader that scopes by
-- the REAL org then missed the row:
--   * the fleet OIDC verifier (platform/shared/identity/oidc_config.go) →
--     ErrNotConfigured → every per-user OIDC token rejected fail-closed;
--   * portal_check_sso_availability (mig 106/138, WHERE s.org_id = p_org_id)
--     → the login page offers no SSO for a freshly-configured in-vpc org;
--   * the admin org-list join (customer-portal organizations.go).
-- Meanwhile role_assignments (Path B's role source) was already real-org
-- keyed, so in-vpc Path B was split across two different org keys.
--
-- This migration repairs the data; the application change stops writing the
-- sentinel into org_id and scopes RLS on the real org.
--
-- The table only exists on enterprise deployments (mig 108 is enterprise), so
-- every statement is existence-guarded — same posture as core mig 106/143,
-- which touch the same table.
--
-- RLS NOTE (the WITH CHECK trap): the repair CANNOT be done by setting
-- app.current_org_id. Scoping to '__platform__' lets USING match the stale
-- rows but makes WITH CHECK reject the repaired value; scoping to the real org
-- makes USING match nothing. The UPDATE must therefore run with RLS genuinely
-- out of the way. We toggle FORCE off and back on within this transaction —
-- ALTER TABLE needs only table ownership (the migration runner owns these
-- tables; nothing re-owns them) and takes ACCESS EXCLUSIVE, so no concurrent
-- session can observe the un-FORCEd window. This deliberately does NOT rely on
-- the migration role holding BYPASSRLS, which is not guaranteed (mig 098 grants
-- BYPASSRLS only to axonflow_platform_admin).

BEGIN;

DO $$
DECLARE
    v_deployment_org VARCHAR(255);
    v_repaired       INTEGER;
    v_has_sentinel   BOOLEAN;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'sso_configurations'
    ) THEN
        RAISE NOTICE 'Migration 145: sso_configurations does not exist (community deployment) - skipping';
        RETURN;
    END IF;

    -- Nothing to repair on a deployment that never wrote the sentinel (every
    -- SaaS deployment, and any in-vpc deployment configured before the
    -- getSSOTenantID collapse landed).
    --
    -- This MUST probe all three tables, not just sso_configurations. The
    -- satellites can hold sentinel rows while the config no longer does: only
    -- sso_sessions has an FK to the config (ON DELETE CASCADE, enterprise mig
    -- 108), so if an admin deletes and re-creates the config on a fixed portal
    -- — the remediation getSSOTenantID's UPGRADE NOTE prescribes — the new
    -- config row is correctly keyed while sso_login_attempts keeps its
    -- '__platform__' rows. Probing only the config would report "nothing to
    -- repair" and strand them permanently: a re-run would take the same early
    -- exit, because it keys on the one table that is already fixed. Stranded
    -- satellites are not cosmetic — the org-scoped portal reader cannot see the
    -- historical login attempts, and DeleteSessionsByTenant silently revokes
    -- nothing while the delete path still audits "sessions revoked".
    SELECT EXISTS (SELECT 1 FROM sso_configurations WHERE org_id = '__platform__')
        INTO v_has_sentinel;
    IF NOT v_has_sentinel AND to_regclass('public.sso_sessions') IS NOT NULL THEN
        SELECT EXISTS (SELECT 1 FROM sso_sessions WHERE org_id = '__platform__')
            INTO v_has_sentinel;
    END IF;
    IF NOT v_has_sentinel AND to_regclass('public.sso_login_attempts') IS NOT NULL THEN
        SELECT EXISTS (SELECT 1 FROM sso_login_attempts WHERE org_id = '__platform__')
            INTO v_has_sentinel;
    END IF;
    IF NOT v_has_sentinel THEN
        RAISE NOTICE 'Migration 145: no __platform__-keyed org_id rows in sso_configurations/sso_sessions/sso_login_attempts - nothing to repair';
        RETURN;
    END IF;

    -- The real org for an in-vpc deployment is ORG_ID, surfaced to migrations
    -- as app.deployment_org_id by the agent's migration runner (the same GUC
    -- mig 094's Pass-2 backfill reads). In in-vpc the deployment org IS the
    -- portal login identity AND the licensed fleet org — the agent fatals at
    -- boot on a license/ORG_ID mismatch — so it is exactly the value the
    -- portal will scope future writes to and the fleet will verify against.
    v_deployment_org := NULLIF(current_setting('app.deployment_org_id', true), '');

    IF v_deployment_org IS NULL THEN
        RAISE WARNING 'Migration 145: sso_configurations has __platform__-keyed org_id rows but app.deployment_org_id is unset - leaving them alone. Per-user OIDC tokens (Path B) stay rejected until an operator re-points org_id to the deployment org.';
        RETURN;
    END IF;

    -- Never stamp an org that does not exist.
    --
    -- NB this check alone does NOT catch the 'local-dev-org' fallback: mig 094
    -- SEEDS that org row, so it always exists. The dev-sentinel case is gated
    -- separately below.
    IF NOT EXISTS (SELECT 1 FROM organizations WHERE org_id = v_deployment_org) THEN
        RAISE WARNING 'Migration 145: app.deployment_org_id=% has no organizations row - refusing to stamp a non-existent org onto sso_* rows. Set ORG_ID to the deployment org and re-run.', v_deployment_org;
        RETURN;
    END IF;

    -- #2320 posture, mirroring mig 094: an operator who deployed a real stack
    -- and forgot ORG_ID collapses to the same 'local-dev-org' the legitimate
    -- docker-compose/community default uses. app.deployment_kind tells the two
    -- apart. Stamping the dev sentinel onto a production deployment would swap
    -- one wrong org key for another while LOOKING repaired, and the repair is
    -- forward-only (the predicate below matches only '__platform__', so a
    -- re-run with the right ORG_ID would not correct it).
    --
    -- Largely belt-and-braces: the agent fatals at boot on a license/ORG_ID
    -- mismatch (run.go) BEFORE migrations run, and mig 094's own precondition
    -- would already have raised. Cheap to assert anyway.
    IF v_deployment_org = 'local-dev-org'
       AND COALESCE(current_setting('app.deployment_kind', true), 'dev') <> 'dev' THEN
        RAISE WARNING 'Migration 145: app.deployment_org_id is the dev sentinel ''local-dev-org'' on a % deployment - refusing to stamp it onto sso_* rows. Set ORG_ID to the real deployment org and re-run.',
            current_setting('app.deployment_kind', true);
        RETURN;
    END IF;

    -- Refuse to CREATE ambiguity. org_id is not UNIQUE (only tenant_id is), so
    -- a deployment that configured SSO pre-#2808 (row keyed on the real org)
    -- and then re-created it post-#2808 (row keyed on the sentinel) holds TWO
    -- rows. Repairing the sentinel row would give both the same org_id, and
    -- every org-keyed reader takes the first arbitrary match with no ORDER BY
    -- — the fleet verifier (oidc_config.go) could then load the STALE issuer
    -- and reject every Path B token non-deterministically, which is the exact
    -- failure this migration exists to remove. Leave it to the operator.
    IF EXISTS (
        SELECT 1 FROM sso_configurations
        WHERE org_id = v_deployment_org AND tenant_id <> '__platform__'
    ) THEN
        RAISE WARNING 'Migration 145: org % already has a non-platform sso_configurations row, and a __platform__-keyed row also exists. Repairing would leave TWO configs for one org and make the fleet OIDC verifier pick arbitrarily. Delete the stale config (keep the one the portal shows) and re-run.', v_deployment_org;
        RETURN;
    END IF;

    -- See the RLS NOTE above: FORCE off → repair → FORCE back on, all inside
    -- this transaction's ACCESS EXCLUSIVE lock.
    ALTER TABLE sso_configurations NO FORCE ROW LEVEL SECURITY;

    UPDATE sso_configurations SET org_id = v_deployment_org WHERE org_id = '__platform__';
    GET DIAGNOSTICS v_repaired = ROW_COUNT;

    ALTER TABLE sso_configurations FORCE ROW LEVEL SECURITY;

    RAISE NOTICE 'Migration 145: re-pointed % sso_configurations row(s) org_id __platform__ -> %', v_repaired, v_deployment_org;

    -- Satellite tables carry the same NOT NULL org_id + FORCE RLS shape (mig
    -- 106) and were written by the same conflation. Left alone, historical
    -- login attempts stay invisible to the org-scoped portal reader and stale
    -- sessions cannot be revoked by DeleteSessionsByTenant.
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'sso_sessions'
    ) THEN
        ALTER TABLE sso_sessions NO FORCE ROW LEVEL SECURITY;
        UPDATE sso_sessions SET org_id = v_deployment_org WHERE org_id = '__platform__';
        GET DIAGNOSTICS v_repaired = ROW_COUNT;
        ALTER TABLE sso_sessions FORCE ROW LEVEL SECURITY;
        RAISE NOTICE 'Migration 145: re-pointed % sso_sessions row(s)', v_repaired;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'sso_login_attempts'
    ) THEN
        ALTER TABLE sso_login_attempts NO FORCE ROW LEVEL SECURITY;
        UPDATE sso_login_attempts SET org_id = v_deployment_org WHERE org_id = '__platform__';
        GET DIAGNOSTICS v_repaired = ROW_COUNT;
        ALTER TABLE sso_login_attempts FORCE ROW LEVEL SECURITY;
        RAISE NOTICE 'Migration 145: re-pointed % sso_login_attempts row(s)', v_repaired;
    END IF;
END $$;

-- ============================================================================
-- Pre-auth org lookup for the SAML login path
-- ============================================================================
-- With org_id decoupled from tenant_id, the SAML login path can no longer scope
-- RLS on the tenant id it takes from the URL (/auth/saml/{tenantID}/...): in
-- in-vpc that is '__platform__' while the row now lives under the real org.
-- The path is PRE-AUTH — it has only the URL's tenant id and no session — so it
-- needs an RLS-exempt way to learn which org a config belongs to. Same posture
-- and blast radius as portal_check_sso_availability (mig 104/106/138), which is
-- already a pre-auth SECURITY DEFINER probe over this table: this returns only
-- the org id of a config the caller already named, no config contents.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'sso_configurations'
    ) THEN
        RAISE NOTICE 'Migration 145: sso_configurations absent - skipping sso_config_org_for_tenant helper';
        RETURN;
    END IF;

    EXECUTE $fn$
        CREATE OR REPLACE FUNCTION sso_config_org_for_tenant(p_tenant_id VARCHAR)
        RETURNS VARCHAR
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $body$
        DECLARE
            v_org_id VARCHAR(255);
        BEGIN
            IF p_tenant_id IS NULL OR p_tenant_id = '' THEN
                RETURN NULL;
            END IF;
            SELECT org_id INTO v_org_id
            FROM sso_configurations
            WHERE tenant_id = p_tenant_id
            LIMIT 1;
            RETURN v_org_id;  -- NULL when the tenant has no SSO config
        END;
        $body$;
    $fn$;

    EXECUTE $c$
        COMMENT ON FUNCTION sso_config_org_for_tenant(VARCHAR) IS
            'SECURITY DEFINER pre-auth lookup: returns sso_configurations.org_id '
            'for a tenant_id, or NULL. Bypasses FORCE RLS (mig 106) so the SAML '
            'login path — which is pre-auth and holds only the URL tenant id — '
            'can set app.current_org_id before reading the config. In in-vpc the '
            'tenant id is the __platform__ sentinel while org_id is the real org '
            '(#2960). Returns the org id only, never config contents.'
    $c$;

    -- Owner hardening — pin to axonflow_platform_admin (BYPASSRLS, NOT
    -- SUPERUSER) so the definer's rights are the narrow platform-admin set
    -- rather than the migration runner's. Mirrors mig 109. Idempotent.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        EXECUTE 'ALTER FUNCTION sso_config_org_for_tenant(VARCHAR) OWNER TO axonflow_platform_admin';
        RAISE NOTICE 'Migration 145: sso_config_org_for_tenant re-owned to axonflow_platform_admin';
    ELSE
        RAISE NOTICE 'Migration 145: axonflow_platform_admin not present (mig 098 not yet run); helper stays on migration runner owner';
    END IF;

    -- Postgres default-GRANTs EXECUTE to PUBLIC on CREATE FUNCTION. Left as-is,
    -- a SECURITY DEFINER function owned by a BYPASSRLS role would let ANY role
    -- in the database read sso_configurations.org_id for a guessed tenant_id,
    -- straight through FORCE RLS. Revoke first, then grant narrowly — the same
    -- order mig 104/138 use for portal_check_sso_availability.
    EXECUTE 'REVOKE EXECUTE ON FUNCTION sso_config_org_for_tenant(VARCHAR) FROM PUBLIC';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION sso_config_org_for_tenant(VARCHAR) TO axonflow_app_role';
        RAISE NOTICE 'Migration 145: EXECUTE on sso_config_org_for_tenant revoked from PUBLIC, granted to axonflow_app_role';
    END IF;
END $$;

-- ============================================================================
-- Verification — fail loudly if any artifact is missing (Principle 3).
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'sso_configurations'
    ) THEN
        RETURN;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_proc WHERE proname = 'sso_config_org_for_tenant'
    ) THEN
        RAISE EXCEPTION 'Migration 145 failed: sso_config_org_for_tenant not created';
    END IF;

    -- FORCE RLS must be back on for every table we toggled — a migration that
    -- left a security boundary off would be far worse than the bug it fixes.
    IF EXISTS (
        SELECT 1 FROM pg_class
        WHERE relname = 'sso_configurations' AND relnamespace = 'public'::regnamespace
          AND NOT relforcerowsecurity
    ) THEN
        RAISE EXCEPTION 'Migration 145 failed: sso_configurations FORCE RLS was not restored';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_class
        WHERE relname = 'sso_sessions' AND relnamespace = 'public'::regnamespace
          AND NOT relforcerowsecurity
    ) THEN
        RAISE EXCEPTION 'Migration 145 failed: sso_sessions FORCE RLS was not restored';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_class
        WHERE relname = 'sso_login_attempts' AND relnamespace = 'public'::regnamespace
          AND NOT relforcerowsecurity
    ) THEN
        RAISE EXCEPTION 'Migration 145 failed: sso_login_attempts FORCE RLS was not restored';
    END IF;

    RAISE NOTICE 'Migration 145 verified: org_id decoupled from tenant_id, helper present, FORCE RLS intact';
END $$;

COMMIT;
