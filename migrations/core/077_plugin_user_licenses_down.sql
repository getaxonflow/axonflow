-- Down migration for 077: drop plugin_user_licenses table.
-- Idempotent.

DROP INDEX IF EXISTS idx_plugin_lic_jti;
DROP INDEX IF EXISTS idx_plugin_lic_email;
DROP INDEX IF EXISTS idx_plugin_lic_active;
DROP INDEX IF EXISTS idx_plugin_lic_tenant;

DROP TABLE IF EXISTS plugin_user_licenses;

DO $$
BEGIN
    RAISE NOTICE 'Migration 077 down: dropped plugin_user_licenses table';
END $$;
