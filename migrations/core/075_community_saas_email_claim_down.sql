-- Down migration for 075: drop email-claim columns + index from community_saas_registrations.
-- Idempotent.

DROP INDEX IF EXISTS idx_csaas_reg_claimed_email;

ALTER TABLE community_saas_registrations
    DROP COLUMN IF EXISTS claimed_at,
    DROP COLUMN IF EXISTS claimed_by_email;

DO $$
BEGIN
    RAISE NOTICE 'Migration 075 down: dropped claimed_by_email + claimed_at + index';
END $$;
