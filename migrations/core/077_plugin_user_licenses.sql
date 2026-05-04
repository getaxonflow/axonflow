-- Migration 077: Plugin user licenses for paid Pro tier (W4)
-- Date: 2026-05-04
-- Context: Tenant durability + claim work (PRD: axonflow-internal-docs/prds/PRD_TENANT_DURABILITY_AND_CLAIM.md,
--          ADR: axonflow-enterprise/technical-docs/architecture-decisions/ADR-049-plugin-claimed-license-tier.md).
--
-- Provides:
--   plugin_user_licenses — DB-resident entitlements for paid plugin-claimed
--                          and (future) plugin-subscription tiers. Source of
--                          truth for ENFORCEMENT (retention, quota, capabilities,
--                          support level). Token (sent by plugin in
--                          X-License-Token header) carries identity + coarse
--                          tier; this table carries the mutable entitlements.
--
-- Why hybrid schema (hot indexed columns + JSONB):
--   Per ADR-049 sections 4 + 9, the agent middleware queries this row on
--   every request. Hot fields (tier, expires_at, revoked_at, license_token_jti)
--   are top-level indexed columns for fast enforcement queries. Everything else
--   lives in JSONB so we can add capabilities (e.g. for Premium v2) without
--   schema migrations.
--
-- Why per-request validation instead of session caching (ADR-049 section 2):
--   - Plugin-claim revocation must be effective within ~60s (chargeback / dispute)
--   - Per-tenant DB row is already cached in the agent's existing tenant lookup
--   - Avoids stale-token-after-revoke window that session caching would introduce
--
-- Depends on: 075_community_saas_email_claim (claimed_by_email column on
--             community_saas_registrations — referenced via FK from this table)

CREATE TABLE IF NOT EXISTS plugin_user_licenses (
    license_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Identity binding (FK to the registrations table — same DB per ADR-049 section 6)
    tenant_id           VARCHAR(255) NOT NULL REFERENCES community_saas_registrations(tenant_id),
    claimed_by_email    VARCHAR(255) NOT NULL,

    -- Hot indexed columns (enforcement path: agent middleware reads these on every request)
    tier                VARCHAR(50)  NOT NULL CHECK (tier IN ('plugin-claimed', 'plugin-subscription')),
    expires_at          TIMESTAMP WITH TIME ZONE,         -- NULL for one-time purchases (Pro v1); future timestamp for future subscription tier
    revoked_at          TIMESTAMP WITH TIME ZONE,
    license_token_jti   VARCHAR(64) NOT NULL UNIQUE,      -- JWT-style jti claim; enables per-token revocation + audit trail
    rotation_generation INTEGER NOT NULL DEFAULT 1,        -- which signing-key generation issued this token

    -- Mutable entitlements as JSONB so we can add capabilities without migrations
    -- For tier=plugin-claimed (Pro v1):
    --   { "retention_days": 365, "daily_event_quota": 10000, "email_recovery": true,
    --     "license_token_recovery": true, "read_tools": true, "write_hooks": true,
    --     "advanced_hosted_capabilities": [], "support_level": "best_effort_email" }
    -- For tier=plugin-subscription (Premium v2 placeholder; not issued in v1):
    --   { ..., "daily_event_quota": 50000, "support_level": "priority_email_no_sla",
    --         "advanced_hosted_capabilities": ["map_plans", ...] }
    entitlements        JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Audit + payment trail (for refund / dispute / accounting reconciliation)
    stripe_customer_id  VARCHAR(255),
    stripe_session_id   VARCHAR(255),
    issued_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    revocation_reason   TEXT
);

-- Hot indexes for the enforcement path. agent middleware queries by tenant_id
-- on every request, so this needs to be fast.
CREATE INDEX IF NOT EXISTS idx_plugin_lic_tenant   ON plugin_user_licenses(tenant_id);

-- Active-only partial index — most queries filter to non-revoked rows.
-- Partial index is much smaller than a full index, faster lookups.
CREATE INDEX IF NOT EXISTS idx_plugin_lic_active   ON plugin_user_licenses(tenant_id) WHERE revoked_at IS NULL;

-- Email lookups for the recovery flow + per-email-tenant-cap queries.
CREATE INDEX IF NOT EXISTS idx_plugin_lic_email    ON plugin_user_licenses(claimed_by_email);

-- jti lookups for token revocation + audit trail correlation.
-- license_token_jti is already UNIQUE-constrained (creates an implicit index),
-- but explicit naming makes the index discoverable in pg_indexes for ops.
CREATE INDEX IF NOT EXISTS idx_plugin_lic_jti      ON plugin_user_licenses(license_token_jti);

DO $$
BEGIN
    RAISE NOTICE 'Migration 077: plugin_user_licenses table created (W4 paid Pro tier infrastructure)';
END $$;
