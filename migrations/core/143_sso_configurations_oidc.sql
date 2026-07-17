-- Migration 143: Extend sso_configurations for OIDC providers (#2924, epic #2919)
-- Date: 2026-07-16
-- Purpose: Path B (IdP-issued OIDC/JWKS) per-user identity needs per-tenant
--          OIDC verifier configuration: issuer, audience, JWKS URI, and a
--          claim-mapping. The existing sso_configurations table (created by
--          enterprise mig 108, org-scoped by core mig 106) is SAML-shaped;
--          this adds a provider_type discriminator plus the OIDC columns.
--
-- The table only exists on enterprise deployments (mig 108 is enterprise),
-- so every statement is existence-guarded — identical posture to core mig
-- 106, which touches the same table. RLS is untouched: mig 106's FORCE RLS +
-- app.current_org_id isolation policy already covers new columns.

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'sso_configurations'
    ) THEN
        -- Discriminator: 'saml' (all pre-existing rows) or 'oidc'.
        ALTER TABLE sso_configurations
            ADD COLUMN IF NOT EXISTS provider_type VARCHAR(16) NOT NULL DEFAULT 'saml';

        ALTER TABLE sso_configurations DROP CONSTRAINT IF EXISTS sso_configurations_provider_type_chk;
        ALTER TABLE sso_configurations
            ADD CONSTRAINT sso_configurations_provider_type_chk
            CHECK (provider_type IN ('saml', 'oidc'));

        -- OIDC verifier inputs. NULL for SAML rows; the application layer
        -- requires all three non-empty before an OIDC config is usable.
        ALTER TABLE sso_configurations
            ADD COLUMN IF NOT EXISTS oidc_issuer TEXT;
        ALTER TABLE sso_configurations
            ADD COLUMN IF NOT EXISTS oidc_audience TEXT;
        ALTER TABLE sso_configurations
            ADD COLUMN IF NOT EXISTS oidc_jwks_uri TEXT;

        -- Claim mapping, e.g. {"email": "email"}. Which token claim carries
        -- the canonical identity. Defaults applied in the application layer.
        ALTER TABLE sso_configurations
            ADD COLUMN IF NOT EXISTS oidc_claim_mapping JSONB NOT NULL DEFAULT '{}'::jsonb;

        -- Backfill: any pre-existing row created with provider='oidc' (the
        -- value was already whitelisted by the portal handler even though the
        -- table had no OIDC columns) is an OIDC config, not SAML.
        UPDATE sso_configurations SET provider_type = 'oidc'
        WHERE provider = 'oidc' AND provider_type = 'saml';

        RAISE NOTICE 'Migration 143: sso_configurations extended with provider_type + OIDC columns';
    ELSE
        RAISE NOTICE 'Migration 143: sso_configurations does not exist (community deployment) - skipping';
    END IF;
END $$;

-- Verification — fail loudly if any artifact is missing (Principle 3).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'sso_configurations'
    ) THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = 'sso_configurations' AND column_name = 'provider_type') THEN
            RAISE EXCEPTION 'Migration 143 failed: provider_type column not created';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = 'sso_configurations' AND column_name = 'oidc_issuer') THEN
            RAISE EXCEPTION 'Migration 143 failed: oidc_issuer column not created';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = 'sso_configurations' AND column_name = 'oidc_audience') THEN
            RAISE EXCEPTION 'Migration 143 failed: oidc_audience column not created';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = 'sso_configurations' AND column_name = 'oidc_jwks_uri') THEN
            RAISE EXCEPTION 'Migration 143 failed: oidc_jwks_uri column not created';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = 'sso_configurations' AND column_name = 'oidc_claim_mapping') THEN
            RAISE EXCEPTION 'Migration 143 failed: oidc_claim_mapping column not created';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.constraint_column_usage
                       WHERE table_name = 'sso_configurations' AND constraint_name = 'sso_configurations_provider_type_chk') THEN
            RAISE EXCEPTION 'Migration 143 failed: provider_type CHECK constraint not created';
        END IF;
        RAISE NOTICE 'Migration 143 verified: OIDC columns + provider_type CHECK present';
    END IF;
END $$;

COMMIT;
