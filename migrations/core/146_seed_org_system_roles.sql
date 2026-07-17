-- Migration 146: seed the resolver-recognized system roles for every org
--                (#2963, epic #2919)
-- Date: 2026-07-17
-- Purpose: Path B (IdP-issued OIDC) resolves a developer's role from the
--          SCIM-synced directory, keyed on custom_roles.name. But no org
--          created after mig 023 has ANY roles — 023's seed selects
--          FROM (SELECT DISTINCT tenant_id FROM dynamic_policies), so an org
--          with no policies at migration time gets nothing, and nothing else
--          seeds them (the roles CRUD API + EnsureDefaultRoles are unmounted
--          dead code). GET /api/v1/scim/roles then returns [], and the SCIM
--          group->role mapping step has no role_id to use — Path B cannot be
--          completed. This seeds the roles the fleet resolver recognizes, for
--          every org, and keeps new orgs seeded via a trigger.
--
-- The six roles are exactly the names platform/shared/identity/
-- scim_role_resolver.go recognizes: the rolePrecedence set
-- (owner > policy_admin > developer > member > viewer) PLUS admin, which the
-- resolver matches separately (a role whose name is 'admin' OR whose
-- permissions contain '*' resolves to admin). Path B most needs a group that
-- maps to tenant-wide access, so admin MUST exist.
--
-- Permission sets use the canonical vocabulary in
-- ee/platform/customer-portal/api/roles/types.go (AllPermissions) and match the
-- existing definitions in mig 023 + roles/service.go EnsureDefaultRoles for the
-- three roles those already define, so an org that was seeded pre-146 sees no
-- change (ON CONFLICT DO NOTHING). CRITICAL: owner gets the EXPLICIT full
-- permission list, NOT ['*'] — the resolver short-circuits a '*' permission to
-- 'admin', so a wildcard owner would silently collapse into admin. owner still
-- reads tenant-wide because RoleCanReadTenant matches the NAME 'owner'.
--
-- #2960 alignment: custom_roles is keyed on the REAL org_id (mig 111 renamed
-- tenant_id -> org_id) and has RLS ENABLED with an org_id isolation policy
-- (USING + WITH CHECK on org_id = current_setting('app.current_org_id')). The
-- seeder is therefore SECURITY DEFINER owned by axonflow_platform_admin, which
-- bypasses that policy (BYPASSRLS), so the INSERTs need no app.current_org_id
-- set — same posture as mig 145's helper. NB custom_roles is ENABLE, not FORCE,
-- so the table OWNER also bypasses the policy; either way the seeder's INSERTs
-- are not policy-checked. Its direct EXECUTE is revoked from PUBLIC anyway
-- (Postgres default-grants it; a SECURITY DEFINER function owned by a
-- privileged role must not be callable by every role).

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'custom_roles'
    ) THEN
        RAISE NOTICE 'Migration 146: custom_roles does not exist - skipping';
        RETURN;
    END IF;

    -- The workhorse: seed the six system roles for one org, idempotently. Named
    -- so a trigger, the backfill, and manual repair all share one definition.
    -- Permission sets are the SINGLE source of truth; keep them in lockstep with
    -- roles/types.go + roles/service.go EnsureDefaultRoles.
    EXECUTE $fn$
        CREATE OR REPLACE FUNCTION ensure_org_system_roles(p_org_id VARCHAR)
        RETURNS INTEGER
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $body$
        DECLARE
            v_created INTEGER := 0;
        BEGIN
            IF p_org_id IS NULL OR p_org_id = '' THEN
                RETURN 0;
            END IF;

            -- (name, display_name, description, permissions, is_system)
            -- admin: '*' — the resolver maps a '*' permission (or the name
            --   'admin') to admin. Full access.
            -- owner: the EXPLICIT full list — NEVER '*', or it collapses to
            --   admin. Tenant-wide reads come from RoleCanReadTenant('owner').
            -- policy_admin / viewer: identical to mig 023 + EnsureDefaultRoles.
            -- developer: viewer + connector:execute (runs queries, no writes).
            -- member: read-oriented, one notch above viewer (adds user:read).
            --   member is defined nowhere else in the codebase; this default is
            --   called out in the PR for sign-off.
            INSERT INTO custom_roles (id, org_id, name, display_name, description, permissions, is_system, created_by)
            VALUES
                ('role_admin_'        || p_org_id, p_org_id, 'admin',        'Administrator',        'Full system access',
                 '["*"]'::jsonb, true, 'system'),
                ('role_owner_'        || p_org_id, p_org_id, 'owner',        'Owner',                'Full access; tenant-wide reads',
                 '["policy:read","policy:write","policy:delete","connector:read","connector:write","connector:execute","user:read","user:write","audit:read","settings:read","settings:write","sso:configure","roles:read","roles:write"]'::jsonb, true, 'system'),
                ('role_policy_admin_' || p_org_id, p_org_id, 'policy_admin', 'Policy Administrator', 'Can manage policies',
                 '["policy:read","policy:write","policy:delete","audit:read"]'::jsonb, true, 'system'),
                ('role_developer_'    || p_org_id, p_org_id, 'developer',    'Developer',            'Read + run queries; no admin',
                 '["policy:read","connector:read","connector:execute","audit:read"]'::jsonb, true, 'system'),
                ('role_member_'       || p_org_id, p_org_id, 'member',       'Member',               'Read-oriented team member',
                 '["policy:read","connector:read","audit:read","user:read"]'::jsonb, true, 'system'),
                ('role_viewer_'       || p_org_id, p_org_id, 'viewer',       'Viewer',               'Read-only access',
                 '["policy:read","connector:read","audit:read"]'::jsonb, true, 'system')
            -- Bare ON CONFLICT (any constraint), not just (org_id,name): the
            -- synthetic id 'role_<name>_<org_id>' can collide on the PK across
            -- different (org_id,name) pairs when an org_id contains '_'
            -- (e.g. org 'a_b'+name 'c' and org 'b'+name 'c_a' both yield
            -- 'role_c_a_b'). An uncaught unique_violation here would roll back
            -- the triggering org INSERT; skipping the row keeps org creation
            -- safe. Idempotency is unchanged for the normal case.
            ON CONFLICT DO NOTHING;

            GET DIAGNOSTICS v_created = ROW_COUNT;
            RETURN v_created;
        END;
        $body$;
    $fn$;

    EXECUTE $c$
        COMMENT ON FUNCTION ensure_org_system_roles(VARCHAR) IS
            'Idempotently seeds the six fleet-resolver-recognized system roles '
            '(admin/owner/policy_admin/developer/member/viewer) for an org. '
            'SECURITY DEFINER so it bypasses the custom_roles RLS policy; owned by '
            'axonflow_platform_admin. Called by the organizations AFTER INSERT '
            'trigger, the mig 146 backfill, and available for manual repair. '
            'Permission sets are lockstep with roles/types.go + '
            'EnsureDefaultRoles (#2963).'
    $c$;

    -- The trigger function. SECURITY DEFINER so it runs as the workhorse's
    -- owner regardless of who inserted the org (register_org, mig 094 seed,
    -- promote_deployment_org_license, the portal admin API, or raw SQL). A
    -- trigger is used rather than wiring one org-creation path so no future org
    -- writer can forget to seed roles (the #2896 census lesson).
    EXECUTE $tf$
        CREATE OR REPLACE FUNCTION trg_ensure_org_system_roles()
        RETURNS TRIGGER
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $body$
        BEGIN
            PERFORM ensure_org_system_roles(NEW.org_id);
            RETURN NEW;
        END;
        $body$;
    $tf$;

    DROP TRIGGER IF EXISTS seed_org_system_roles ON organizations;
    CREATE TRIGGER seed_org_system_roles
        AFTER INSERT ON organizations
        FOR EACH ROW
        EXECUTE FUNCTION trg_ensure_org_system_roles();

    -- Backfill every existing org. Covers the deployment org mig 094 seeded
    -- before this trigger existed, and every org created since mig 023 whose
    -- roles were never seeded because it had no dynamic_policies.
    DECLARE
        v_org   RECORD;
        v_total INTEGER := 0;
        v_n     INTEGER;
    BEGIN
        FOR v_org IN SELECT org_id FROM organizations LOOP
            v_n := ensure_org_system_roles(v_org.org_id);
            v_total := v_total + v_n;
        END LOOP;
        RAISE NOTICE 'Migration 146: backfilled % system-role row(s) across existing orgs', v_total;
    END;

    -- Owner hardening — pin both functions to axonflow_platform_admin
    -- (BYPASSRLS, NOT SUPERUSER) so the definer's rights are the narrow
    -- platform-admin set and the INSERTs bypass the custom_roles RLS policy. Mirrors
    -- mig 109/145. Gated on the role existing (absent pre-mig-098 / in dev,
    -- where the runner owns them and typically bypasses RLS anyway). Idempotent.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        EXECUTE 'ALTER FUNCTION ensure_org_system_roles(VARCHAR) OWNER TO axonflow_platform_admin';
        EXECUTE 'ALTER FUNCTION trg_ensure_org_system_roles() OWNER TO axonflow_platform_admin';
        RAISE NOTICE 'Migration 146: role seeders re-owned to axonflow_platform_admin';
    ELSE
        RAISE NOTICE 'Migration 146: axonflow_platform_admin not present (mig 098 not yet run); seeders stay on migration runner owner';
    END IF;

    -- Postgres default-GRANTs EXECUTE to PUBLIC on CREATE FUNCTION. On a
    -- privileged SECURITY DEFINER function that INSERTs into custom_roles
    -- unchecked, PUBLIC-callable is a write-through-RLS primitive for any role
    -- — revoke, then grant narrowly. The trigger function is invoked by the
    -- trigger machinery, not called, so it needs no EXECUTE grant.
    EXECUTE 'REVOKE EXECUTE ON FUNCTION ensure_org_system_roles(VARCHAR) FROM PUBLIC';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION ensure_org_system_roles(VARCHAR) TO axonflow_app_role';
    END IF;

    RAISE NOTICE 'Migration 146: system-role seeder + organizations trigger installed';
END $$;

-- Verification — fail loudly if any artifact is missing (Principle 3).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'custom_roles'
    ) THEN
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'ensure_org_system_roles') THEN
        RAISE EXCEPTION 'Migration 146 failed: ensure_org_system_roles not created';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'seed_org_system_roles' AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION 'Migration 146 failed: seed_org_system_roles trigger not created';
    END IF;
    -- PUBLIC must not be able to EXECUTE the seeder.
    IF has_function_privilege('public', 'ensure_org_system_roles(character varying)', 'EXECUTE') THEN
        RAISE EXCEPTION 'Migration 146 failed: PUBLIC can EXECUTE ensure_org_system_roles';
    END IF;

    RAISE NOTICE 'Migration 146 verified: seeder + trigger present, PUBLIC execute revoked';
END $$;

COMMIT;
