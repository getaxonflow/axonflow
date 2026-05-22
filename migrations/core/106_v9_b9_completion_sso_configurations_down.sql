-- Rollback for migration 106: sso_configurations org_id column + FORCE RLS
--
-- Restores the pre-106 state: drop FORCE, drop org_id policies, restore
-- mig-108 tenant_id policies, drop the new org_id columns.
--
-- WARNING: the portal_check_sso_availability function body is NOT reverted
-- here — mig 104's `_down.sql` handles that. If this rollback runs while
-- mig 104 is still applied, the function will continue to query `s.org_id`
-- which won't exist after this rollback. Coordinate rollback ordering.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sso_configurations') THEN
        ALTER TABLE sso_configurations NO FORCE ROW LEVEL SECURITY;
        ALTER TABLE sso_sessions       NO FORCE ROW LEVEL SECURITY;
        ALTER TABLE sso_login_attempts NO FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS sso_configurations_org_id_isolation ON sso_configurations;
        DROP POLICY IF EXISTS sso_sessions_org_id_isolation       ON sso_sessions;
        DROP POLICY IF EXISTS sso_login_attempts_org_id_isolation ON sso_login_attempts;

        -- Restore the mig-108 tenant_id policies (includes sso_login_attempts).
        CREATE POLICY sso_configurations_tenant_isolation ON sso_configurations
            USING (tenant_id = current_setting('app.tenant_id', true));
        CREATE POLICY sso_sessions_tenant_isolation ON sso_sessions
            USING (tenant_id = current_setting('app.tenant_id', true));
        CREATE POLICY sso_login_attempts_tenant_isolation ON sso_login_attempts
            USING (tenant_id = current_setting('app.tenant_id', true));

        ALTER TABLE sso_configurations DROP COLUMN IF EXISTS org_id;
        ALTER TABLE sso_sessions       DROP COLUMN IF EXISTS org_id;
        ALTER TABLE sso_login_attempts DROP COLUMN IF EXISTS org_id;
    END IF;
END
$$;

COMMIT;
