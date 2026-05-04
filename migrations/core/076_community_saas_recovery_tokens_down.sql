-- Down migration for 076: drop recovery_tokens table.
-- Idempotent.

DROP INDEX IF EXISTS idx_csaas_recovery_email_recent;
DROP INDEX IF EXISTS idx_csaas_recovery_expires;
DROP TABLE IF EXISTS community_saas_recovery_tokens;

DO $$
BEGIN
    RAISE NOTICE 'Migration 076 down: dropped community_saas_recovery_tokens table';
END $$;
