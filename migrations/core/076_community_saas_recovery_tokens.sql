-- Migration 076: Community-SaaS recovery tokens for free email-recovery (W3)
-- Date: 2026-05-03
-- Context: Tenant durability + claim work (PRD: axonflow-internal-docs/prds/PRD_TENANT_DURABILITY_AND_CLAIM.md,
--          companion ADR-049-plugin-claimed-license-tier).
--
-- Provides:
--   community_saas_recovery_tokens — short-lived single-use magic-link tokens.
--                                    Issued by POST /api/v1/recover (email lookup),
--                                    consumed by GET /api/v1/recover/verify.
--
-- Why this exists:
--   Phase 0 confirmed the cross-stack continuity gap: when community-saas stacks
--   rotate, plugin caches hold credentials whose rows don't exist in the new RDS.
--   The W3 recovery flow lets users with email-bound tenants (claimed_by_email set
--   via either registration or POST /api/v1/claim) receive a magic link, click it,
--   and get a fresh tenant_id bound to the same email. Audit history before recovery
--   stays under the previous tenant_id (acceptable for free tier; Pro tier resolves
--   this differently via license-token-bound recovery in W4).
--
-- Token storage: token is HASHED before storage (SHA-256 — not bcrypt because
-- magic links are short-lived (15 min) and we need exact-match lookup, not
-- password-style verification). The plain token is sent in the magic-link URL
-- query parameter and never stored server-side after the row is written.
--
-- Depends on: 075_community_saas_email_claim (claimed_by_email column on registrations)

CREATE TABLE IF NOT EXISTS community_saas_recovery_tokens (
    token_hash         VARCHAR(64) PRIMARY KEY,            -- SHA-256 hex of the magic-link token
    email              VARCHAR(255) NOT NULL,              -- target email for the recovery
    requesting_ip_hash VARCHAR(64),                        -- SHA-256 hex of the IP that requested (for audit)
    created_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMP WITH TIME ZONE NOT NULL,  -- typically NOW() + 15 minutes
    consumed_at        TIMESTAMP WITH TIME ZONE,           -- set when verify endpoint successfully exchanges the token
    consumed_by_tenant VARCHAR(255)                        -- the new tenant_id issued on successful exchange (audit trail)
);

-- Index for cleanup queries (purge expired/consumed tokens older than 7 days)
CREATE INDEX IF NOT EXISTS idx_csaas_recovery_expires
    ON community_saas_recovery_tokens(expires_at);

-- Index for per-email rate limit lookups (block if too many recent tokens for same email)
CREATE INDEX IF NOT EXISTS idx_csaas_recovery_email_recent
    ON community_saas_recovery_tokens(email, created_at DESC);

DO $$
BEGIN
    RAISE NOTICE 'Migration 076: community_saas_recovery_tokens table created';
END $$;
