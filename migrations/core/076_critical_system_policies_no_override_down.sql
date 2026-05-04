-- Down migration for 076.
--
-- Restores the category-based mapping from migration 070 for severity='critical'
-- system policies that this migration promoted to risk_level='critical'.
-- security-sqli reverts to 'high'; PII categories revert to 'medium' (the
-- migration-070 default).
--
-- Note: the migration-070 trigger `enforce_critical_no_override` forced
-- allow_override=FALSE while risk_level was 'critical'. Once we drop back to
-- 'high' or 'medium', allow_override is set to TRUE explicitly so the row
-- matches the post-migration-070 baseline.
--
-- Cascaded `policy_overrides` revocations from the forward migration are
-- intentionally NOT reversed — revocation is auditable history and we don't
-- rewrite it. Operators who need an active override after rolling back
-- should re-create it through the regular POST /api/v1/overrides path.

BEGIN;

UPDATE static_policies
SET risk_level = CASE
        WHEN category IN ('security-sqli', 'prompt-injection', 'secret-leak') THEN 'high'
        ELSE 'medium'
    END,
    allow_override = TRUE
WHERE tier = 'system'
  AND severity = 'critical'
  AND risk_level = 'critical';

COMMIT;
