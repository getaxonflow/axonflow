-- Migration 080: Drop plugin_user_licenses.entitlements JSONB + rename tier values to Pro/Premium
-- Date: 2026-05-05
-- Context: ADR-050 §6 (TierLimits struct shared across quadrants — no JSONB blob) +
--          PRD_TENANT_DURABILITY_AND_CLAIM "Free vs Paid Boundary" lock (Pro / Premium names).
--
-- The earlier (abandoned) parallel-JSONB design from migration 077 carried mutable
-- per-tier capabilities in `entitlements JSONB`. ADR-050 replaces that with the
-- existing `TierLimits` struct in platform/agent/license/tier.go — typed `bool`
-- and `int` fields, looked up by tier value, no DB blob. The blob was load-bearing
-- only for plugin_claim_middleware.go (deleted in a downstream PR) and for the
-- billing webhook's `DefaultEntitlements` config (deleted alongside this migration).
--
-- Tier rename: 'plugin-claimed' → 'Pro' and 'plugin-subscription' → 'Premium' to
-- match the locked product naming. Forward-only because no production rows exist
-- (any rows in staging are test fixtures from the parallel-JSONB launch session).
--
-- Depends on: 077_plugin_user_licenses, 078_plugin_user_licenses_unique_active,
--             079_plugin_user_licenses_session_idempotency

-- 1) Rename existing tier values so the new CHECK constraint accepts them.
UPDATE plugin_user_licenses SET tier = 'Pro'     WHERE tier = 'plugin-claimed';
UPDATE plugin_user_licenses SET tier = 'Premium' WHERE tier = 'plugin-subscription';

-- 2) Replace the tier CHECK constraint. Migration 077 named it
--    plugin_user_licenses_tier_check by the implicit Postgres convention.
ALTER TABLE plugin_user_licenses DROP CONSTRAINT IF EXISTS plugin_user_licenses_tier_check;
ALTER TABLE plugin_user_licenses
    ADD CONSTRAINT plugin_user_licenses_tier_check
    CHECK (tier IN ('Pro', 'Premium'));

-- 3) Drop the entitlements JSONB column. All callers (billing/issuer.go,
--    billing/webhook.go, billing_register.go, plugin_claim_middleware.go)
--    are updated to stop reading/writing this column in the same PR.
ALTER TABLE plugin_user_licenses DROP COLUMN IF EXISTS entitlements;

DO $$
BEGIN
    RAISE NOTICE 'Migration 080: plugin_user_licenses.entitlements dropped; tier values renamed to Pro/Premium per ADR-050';
END $$;
