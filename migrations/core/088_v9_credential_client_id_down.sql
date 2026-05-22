-- Down migration for 088: drop client_id columns + indexes on credential tables.
-- Date: 2026-05-19
-- Pairs with: 088_v9_credential_client_id.sql
--
-- Returns the schema to byte-equal pre-088 state. The forward migration is
-- purely additive (no NOT NULL, no FK, no FORCE RLS) so rollback is loss-
-- free: dropping the columns simply removes the v9 alias data that was
-- copied from tenant_id; tenant_id itself is untouched.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'plugin_user_licenses') THEN
        DROP INDEX IF EXISTS idx_plugin_lic_client_active;
        DROP INDEX IF EXISTS idx_plugin_lic_client_id;
        ALTER TABLE plugin_user_licenses DROP COLUMN IF EXISTS client_id;
        RAISE NOTICE 'Migration 088 DOWN: plugin_user_licenses.client_id + indexes dropped';
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tenants') THEN
        DROP INDEX IF EXISTS idx_tenants_client_id;
        ALTER TABLE tenants DROP COLUMN IF EXISTS client_id;
        RAISE NOTICE 'Migration 088 DOWN: tenants.client_id + index dropped';
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'community_saas_registrations') THEN
        DROP INDEX IF EXISTS uq_csaas_reg_client_id;
        ALTER TABLE community_saas_registrations DROP COLUMN IF EXISTS client_id;
        RAISE NOTICE 'Migration 088 DOWN: community_saas_registrations.client_id + index dropped';
    END IF;
END $$;
