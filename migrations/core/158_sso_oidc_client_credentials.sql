-- Migration 158: sso_configurations OIDC client credentials (#3289, epic #3289)
-- Date: 2026-08-08
-- Issue: #3289
--
-- Adds the two columns an OIDC INTERACTIVE PORTAL LOGIN (browser auth-code
-- flow) needs and that core mig 143 did not add, because 143 provisioned only
-- the Path B TOKEN-VERIFICATION inputs (issuer/audience/jwks_uri - public IdP
-- metadata, no secret):
--
--   - oidc_client_id     TEXT  the OAuth2/OIDC client identifier the portal
--                              presents at the authorize + token endpoints.
--                              Non-secret (it appears in the browser redirect
--                              URL), so it is stored and returned plainly.
--
--   - oidc_client_secret TEXT  the client's confidential secret used at the
--                              token endpoint (client_secret_basic). SENSITIVE.
--                              Stored in a DEDICATED column (never in the
--                              config JSONB), mirroring sp_private_key (mig 108:
--                              "Our private key (encrypted)"): the application
--                              layer marks it json:"-" so it never serializes
--                              into an API response, never logs it, and masks
--                              it on read. At-rest confidentiality is the DB
--                              column's (same posture as sp_private_key /
--                              idp_certificate) - this migration does NOT invent
--                              an app-layer cipher that sp_private_key lacks, so
--                              the two secret columns keep identical handling.
--
-- Both NULL on every existing row (SAML rows never have them; an OIDC row
-- configured for token-verification-only before #3289 simply has no login
-- credentials until an admin adds them). Fully backward compatible: a config
-- without oidc_client_id is not usable for interactive login and the portal
-- reports it as such, exactly as an incomplete SAML config is.
--
-- The table only exists on enterprise deployments (mig 108 is enterprise), so
-- every statement is existence-guarded - identical posture to core mig 106/143,
-- which touch the same table. RLS is untouched: mig 106's FORCE RLS +
-- app.current_org_id isolation policy already covers new columns.
--
-- Idempotency: ADD COLUMN IF NOT EXISTS. Re-runs are no-ops.
-- Rollback: paired 158_sso_oidc_client_credentials_down.sql drops both columns.
-- Depends on: 108_sso_configuration (table), 143 (OIDC columns / provider_type).

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'sso_configurations'
    ) THEN
        ALTER TABLE sso_configurations
            ADD COLUMN IF NOT EXISTS oidc_client_id TEXT;
        ALTER TABLE sso_configurations
            ADD COLUMN IF NOT EXISTS oidc_client_secret TEXT;

        RAISE NOTICE 'Migration 158: sso_configurations OIDC client credentials added (oidc_client_id, oidc_client_secret)';
    ELSE
        RAISE NOTICE 'Migration 158: sso_configurations does not exist (community deployment) - skipping';
    END IF;
END $$;

-- Column documentation.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'sso_configurations' AND column_name = 'oidc_client_id') THEN
        EXECUTE 'COMMENT ON COLUMN sso_configurations.oidc_client_id IS ''OIDC client_id for interactive portal login (#3289). Non-secret; appears in the browser authorize redirect.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'sso_configurations' AND column_name = 'oidc_client_secret') THEN
        EXECUTE 'COMMENT ON COLUMN sso_configurations.oidc_client_secret IS ''OIDC client_secret for the token-endpoint exchange (#3289). SENSITIVE, mirrors sp_private_key: dedicated column, json:"-" in the app, masked on read, never logged.''';
    END IF;
END $$;

-- Verification - fail loudly if either column is missing (Principle 3), but
-- only where the table exists (community deployments have neither).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'sso_configurations'
    ) THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = 'sso_configurations' AND column_name = 'oidc_client_id') THEN
            RAISE EXCEPTION 'Migration 158 failed: oidc_client_id column not created';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = 'sso_configurations' AND column_name = 'oidc_client_secret') THEN
            RAISE EXCEPTION 'Migration 158 failed: oidc_client_secret column not created';
        END IF;
    END IF;
END $$;

COMMIT;
