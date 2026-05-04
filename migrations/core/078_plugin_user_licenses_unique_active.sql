-- Migration 078: Enforce at-most-one-active-row per tenant in plugin_user_licenses
-- Date: 2026-05-04
-- Context: Reviewer P2 finding on PR #1840 (migration 077). The original
--          schema created a non-unique index on tenant_id, allowing multiple
--          non-revoked license rows to accumulate per tenant after rotation,
--          repurchase, or future subscription changes. But the design (PRD
--          + ADR-049) describes agent middleware looking up the tenant's
--          singular active license row by tenant_id and applying that row's
--          entitlements. Without uniqueness enforcement, a tenant with two
--          non-revoked rows would have ambiguous enforcement (which row's
--          entitlements apply? the latest? the most-restrictive?).
--
-- Fix: replace the non-unique idx_plugin_lic_active partial index with a
-- UNIQUE partial index on tenant_id WHERE revoked_at IS NULL. This makes
-- "no two active license rows per tenant" a database-enforced invariant.
-- The W4 keygen tool + Stripe webhook handler MUST mark the prior row
-- revoked_at = NOW() before INSERTing a new row for the same tenant
-- (e.g., on Pro → Premium upgrade or on token rotation that re-issues
-- a license).
--
-- Migration is safe because table is empty at this point (W4 hasn't shipped
-- yet — no rows to violate the new constraint).
--
-- Depends on: 077_plugin_user_licenses

-- Drop the non-unique partial index
DROP INDEX IF EXISTS idx_plugin_lic_active;

-- Re-create as UNIQUE partial index
-- "WHERE revoked_at IS NULL" makes it a partial index on active rows only,
-- so historical revoked rows can coexist freely (preserves audit trail).
CREATE UNIQUE INDEX IF NOT EXISTS idx_plugin_lic_active
    ON plugin_user_licenses(tenant_id)
    WHERE revoked_at IS NULL;

DO $$
BEGIN
    RAISE NOTICE 'Migration 078: plugin_user_licenses now enforces at-most-one-active-row per tenant';
END $$;
