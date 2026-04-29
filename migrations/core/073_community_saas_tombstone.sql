-- Migration 073: Community-SaaS tenant tombstone semantics + lifecycle policy
-- Date: 2026-04-29
-- Context: ADR-048 — plugin Community-SaaS-by-default rollout. The platform's
-- approach to anonymously-issued tenant_ids is "never reuse": once terminated,
-- the row stays in the registrations table forever to hold the PK slot, while
-- its sensitive data (secret_hash) is cleared and any tenant-scoped data in
-- audit/policy/budget tables is cascade-deleted. UUID v4 collision is
-- astronomical, but the tombstone policy makes log/audit/support clarity a
-- design invariant rather than a runtime accident.
--
-- This migration is purely additive:
--   1. Adds `terminated_at` column to `community_saas_registrations` (NULL by default,
--      set by the daily sweep when a tenant goes inactive for >3 months or hits the
--      1-year hard cap).
--   2. Adds a partial index on `last_seen_at` for active rows so the inactivity sweep
--      query stays fast as the tombstone table grows.
--   3. One-shot extension of existing 30-day `expires_at` rows to 1 year so deploying
--      the new lifecycle policy doesn't force re-registration of live tenants on day one.
--
-- Compatible with the existing migration 068. Auth path validates `terminated_at IS NULL`
-- after this column lands; sweep job populates it on inactivity. See
-- platform/agent/community_saas_register.go and (forthcoming) community_saas_sweep.go.

-- 1. Add tombstone column
ALTER TABLE community_saas_registrations
    ADD COLUMN IF NOT EXISTS terminated_at TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN community_saas_registrations.terminated_at IS
    'Set by the daily inactivity sweep when last_seen_at < NOW() - 3 months or '
    'created_at < NOW() - 1 year. Once non-NULL, the auth path rejects this tenant '
    'and tenant-scoped data has been cascade-deleted. The row itself stays forever '
    'so the tenant_id PK slot is never reused.';

-- 2. Partial index for the inactivity sweep query: predicate matches active rows
-- (terminated_at IS NULL) and orders by last_seen_at so range scans terminate early.
CREATE INDEX IF NOT EXISTS idx_csaas_reg_active_inactivity
    ON community_saas_registrations (last_seen_at)
    WHERE terminated_at IS NULL;

-- 3. Partial index for the hard-cap sweep: same shape but ordered by created_at.
CREATE INDEX IF NOT EXISTS idx_csaas_reg_active_created
    ON community_saas_registrations (created_at)
    WHERE terminated_at IS NULL;

-- 4. One-shot extension of existing 30-day expires_at rows to 1 year.
-- Without this, every tenant that registered before this migration would still expire
-- on the original 30-day window, forcing re-register on day one of the new policy.
-- Applied only to active (non-terminated, non-disabled) rows.
UPDATE community_saas_registrations
SET expires_at = created_at + INTERVAL '1 year'
WHERE expires_at < NOW() + INTERVAL '60 days'
  AND terminated_at IS NULL
  AND disabled_at IS NULL;

DO $$
DECLARE
    extended_count INTEGER;
BEGIN
    GET DIAGNOSTICS extended_count = ROW_COUNT;
    RAISE NOTICE 'Migration 073: extended expires_at to 1 year on % active community-saas registration(s)', extended_count;
    RAISE NOTICE 'Migration 073: terminated_at column + active-row partial indexes added';
END $$;
