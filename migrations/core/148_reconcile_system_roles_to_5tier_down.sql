-- Migration 148 DOWN: restore the mig-146 six-role create-if-absent seeder
-- Date: 2026-07-21
--
-- Reverts ensure_org_system_roles to the mig-146 definition (six roles incl.
-- member, ON CONFLICT DO NOTHING). It deliberately does NOT re-create member
-- rows that 148 pruned, nor restore permission bundles 148 rewrote — those are
-- DATA changes, and re-seeding could resurrect a role a customer intentionally
-- reshaped. If a full data rollback is wanted, re-run the mig-146 backfill by
-- hand after this. New orgs created after this down-migration get the mig-146
-- six-role bundles again.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'custom_roles'
    ) THEN
        RAISE NOTICE 'Migration 148 down: custom_roles absent - skipping';
        RETURN;
    END IF;

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
            ON CONFLICT DO NOTHING;

            GET DIAGNOSTICS v_created = ROW_COUNT;
            RETURN v_created;
        END;
        $body$;
    $fn$;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        EXECUTE 'ALTER FUNCTION ensure_org_system_roles(VARCHAR) OWNER TO axonflow_platform_admin';
    END IF;
    EXECUTE 'REVOKE EXECUTE ON FUNCTION ensure_org_system_roles(VARCHAR) FROM PUBLIC';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION ensure_org_system_roles(VARCHAR) TO axonflow_app_role';
    END IF;

    RAISE NOTICE 'Migration 148 down: ensure_org_system_roles restored to mig-146 six-role definition';
END $$;

COMMIT;
