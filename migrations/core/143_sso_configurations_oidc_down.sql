-- Migration 143 DOWN: remove the OIDC extension columns from sso_configurations (#2924).
-- Existence-guarded like the up migration (table is enterprise-only, mig 108).

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'sso_configurations'
    ) THEN
        ALTER TABLE sso_configurations DROP CONSTRAINT IF EXISTS sso_configurations_provider_type_chk;
        ALTER TABLE sso_configurations DROP COLUMN IF EXISTS provider_type;
        ALTER TABLE sso_configurations DROP COLUMN IF EXISTS oidc_issuer;
        ALTER TABLE sso_configurations DROP COLUMN IF EXISTS oidc_audience;
        ALTER TABLE sso_configurations DROP COLUMN IF EXISTS oidc_jwks_uri;
        ALTER TABLE sso_configurations DROP COLUMN IF EXISTS oidc_claim_mapping;
        RAISE NOTICE 'Migration 143 down: OIDC columns removed from sso_configurations';
    END IF;
END $$;

COMMIT;
