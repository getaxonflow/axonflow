-- Migration 075: Add email-claim columns to community_saas_registrations
-- Date: 2026-05-03
-- Context: Tenant durability + claim work (PRD: axonflow-business-docs/product/PRD_TENANT_DURABILITY_AND_CLAIM.md,
--          companion ADR-049-plugin-claimed-license-tier).
--
-- Provides:
--   community_saas_registrations.claimed_by_email — email address bound to a tenant for recovery.
--                                                    Indexed but NOT unique. App-level cap of 3 active
--                                                    tenants per email enforced at claim/recover time.
--   community_saas_registrations.claimed_at      — timestamp when the binding was established.
--   idx_csaas_reg_claimed_email                  — partial index for email recovery lookups.
--
-- Why this exists:
--   The 2026-04-29 18:54Z cluster of 8 "registration not found" auth failures revealed that
--   tenant identity does not survive community-saas stack rotation: when a stack is replaced,
--   the new RDS instance has no row for tenant_ids that had been registered against the old
--   stack. Plugins holding cached credentials silently 401 the next time they make a call.
--
--   Email-bound recovery is the cross-stack continuity layer: a plugin that has set userEmail
--   in its config can present that email at /api/v1/recover, receive a magic link, and have a
--   fresh registration row issued under the same email — preserving the user's identity even
--   though the tenant_id itself rotates.
--
-- Why claimed_by_email is NOT unique:
--   Real users have multiple machines (laptop + work + personal). Forcing 1:1 email-to-tenant
--   would push power users to use throwaway emails or share tenant credentials across machines —
--   both worse than just allowing multiple tenants per email. App-level cap of 3 is enforced at
--   claim/recover time; cap is easy to raise; unique constraint would be hard to remove later.
--
-- Depends on: 068_community_saas_registrations
-- Companion: ADR-049-plugin-claimed-license-tier

ALTER TABLE community_saas_registrations
    ADD COLUMN IF NOT EXISTS claimed_by_email VARCHAR(255),
    ADD COLUMN IF NOT EXISTS claimed_at       TIMESTAMP WITH TIME ZONE;

-- Partial index — only emails that have been claimed.
-- Used by: /api/v1/recover endpoint (lookup all tenants for an email),
-- and by app-level cap check (count tenants per email at claim time).
CREATE INDEX IF NOT EXISTS idx_csaas_reg_claimed_email
    ON community_saas_registrations(claimed_by_email)
    WHERE claimed_by_email IS NOT NULL;

DO $$
BEGIN
    RAISE NOTICE 'Migration 075: claimed_by_email + claimed_at columns added to community_saas_registrations';
END $$;
