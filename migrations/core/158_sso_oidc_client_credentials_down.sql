-- Migration 158 DOWN: remove the OIDC client-credential columns from
-- sso_configurations (#3289). Existence-guarded like the up migration
-- (table is enterprise-only, mig 108).

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'sso_configurations'
    ) THEN
        ALTER TABLE sso_configurations DROP COLUMN IF EXISTS oidc_client_secret;
        ALTER TABLE sso_configurations DROP COLUMN IF EXISTS oidc_client_id;
        RAISE NOTICE 'Migration 158 down: OIDC client-credential columns removed from sso_configurations';
    END IF;
END $$;

COMMIT;
