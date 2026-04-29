-- Down migration 073: Remove community-saas tombstone column + active-row indexes
-- WARNING: Dropping `terminated_at` discards which tenants were inactivity-terminated
-- and which were 1-year-cap terminated. Cascade-deleted tenant-scoped data does NOT
-- come back. Only run this if you intend to also re-extend expires_at on previously
-- terminated rows so they re-authenticate.

DROP INDEX IF EXISTS idx_csaas_reg_active_created;
DROP INDEX IF EXISTS idx_csaas_reg_active_inactivity;

ALTER TABLE community_saas_registrations
    DROP COLUMN IF EXISTS terminated_at;

DO $$
BEGIN
    RAISE NOTICE 'Migration 073 DOWN: terminated_at column + active-row partial indexes dropped';
END $$;
