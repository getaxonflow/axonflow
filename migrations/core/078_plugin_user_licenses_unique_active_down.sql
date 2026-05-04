-- Down migration for 078: revert to non-unique partial index.
-- Idempotent.

DROP INDEX IF EXISTS idx_plugin_lic_active;

-- Re-create as the original non-unique partial index from migration 077
CREATE INDEX IF NOT EXISTS idx_plugin_lic_active
    ON plugin_user_licenses(tenant_id)
    WHERE revoked_at IS NULL;

DO $$
BEGIN
    RAISE NOTICE 'Migration 078 down: reverted plugin_user_licenses idx_plugin_lic_active to non-unique';
END $$;
