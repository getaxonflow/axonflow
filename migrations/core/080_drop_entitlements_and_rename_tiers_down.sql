-- Down migration 080: restore entitlements JSONB column + revert tier CHECK constraint.
--
-- This is a best-effort rollback for development environments only. The
-- entitlements blob's prior contents are NOT recoverable — restored rows
-- start with the default empty object. Production never carried meaningful
-- entitlements data (the parallel-JSONB design was inert scaffolding).

ALTER TABLE plugin_user_licenses ADD COLUMN IF NOT EXISTS entitlements JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE plugin_user_licenses DROP CONSTRAINT IF EXISTS plugin_user_licenses_tier_check;
ALTER TABLE plugin_user_licenses
    ADD CONSTRAINT plugin_user_licenses_tier_check
    CHECK (tier IN ('plugin-claimed', 'plugin-subscription'));

UPDATE plugin_user_licenses SET tier = 'plugin-claimed'      WHERE tier = 'Pro';
UPDATE plugin_user_licenses SET tier = 'plugin-subscription' WHERE tier = 'Premium';

DO $$
BEGIN
    RAISE NOTICE 'Migration 080 down: entitlements JSONB column restored; tier values reverted';
END $$;
