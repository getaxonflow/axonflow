-- Migration 076: Tighten allow_override on severity='critical' system policies.
--
-- Migration 070 added risk_level + allow_override columns and seeded existing
-- rows via category-based mapping. That mapping only flipped allow_override
-- to FALSE for categories `dangerous-command`, `rce`, `privilege-escalation`,
-- `system-destruction` — none of which exist in the seeded system policy set
-- (migration 031). The result: zero system policies had allow_override=FALSE
-- in production, leaving the createOverrideHandler 403 enforcement path
-- (platform/orchestrator/overrides_handler.go:343) unreachable for any user.
--
-- Severity='critical' system policies — auth bypass, time-based blind injection,
-- stacked DROP/DELETE/UPDATE/INSERT/EXEC, government IDs, financial PII —
-- are precisely the cases where session override should be denied at create
-- time. Promoting them to risk_level='critical' also engages the migration 070
-- DB trigger (`enforce_critical_no_override`), which reaffirms allow_override
-- can never be flipped back to TRUE on these rows.
--
-- Scope: only tier='system' rows whose risk_level isn't already 'critical' so
-- the migration is idempotent under repeat application.

BEGIN;

UPDATE static_policies
SET risk_level    = 'critical',
    allow_override = FALSE
WHERE tier = 'system'
  AND severity = 'critical'
  AND risk_level <> 'critical';

-- Revoke any existing active overrides on policies that just became
-- non-overridable. Per ADR-044: "when a policy's allow_override flips to
-- false, all active overrides for that policy are revoked with reason
-- policy_changed". Note that the ADR also specifies an `override_revoked`
-- audit event; SQL migrations cannot reach the application-level audit
-- logger, so the revocation is recorded in revoked_at/revoked_by on the
-- row itself (queryable via /api/v1/overrides?include_revoked=true).
-- Selection criteria mirror the UPDATE above directly rather than reading
-- the just-flipped allow_override column, to keep the intent
-- transaction-order-independent.
UPDATE policy_overrides po
SET revoked_at  = NOW(),
    revoked_by  = 'system:migration-076',
    updated_at  = NOW(),
    updated_by  = 'system:migration-076'
FROM static_policies sp
WHERE po.policy_id::text = sp.id::text
  AND po.policy_type   = 'static'
  AND po.revoked_at    IS NULL
  AND sp.tier          = 'system'
  AND sp.severity      = 'critical';

COMMIT;
