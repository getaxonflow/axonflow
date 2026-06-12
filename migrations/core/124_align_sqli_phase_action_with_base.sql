-- Migration 124: Align SQLi system-policy phase actions with the relaxed base action
-- Purpose: Migrations 066/067 relaxed the base `action` of security-sqli system
--          policies from 'block' to 'warn' (ADR-036 observe-first default), but
--          left `action_request`/`action_response` at the pre-v6.2.0 'block'.
--          The enforcement engine ALWAYS overrides these phase columns with the
--          AXONFLOW_PROFILE DetectionConfig: BuildActionOverrides()
--          (platform/agent/detection_config.go) unconditionally maps
--          `security-sqli`, and every enforcement site passes it to
--          EvaluateRequest/EvaluateResponse, where platform/shared/policy/
--          engine.go (lines ~133/200/295) overwrites GetActionForPhase() with the
--          override. So the phase columns are INERT for enforcement — a fresh
--          `default` profile warns on SQLi regardless of these columns.
--          BUT a stored column that reads 'block' while the product warns
--          misleads readers/reviewers/auditors (it caused a multi-day "does
--          AxonFlow block SQLi?" investigation) AND mislabels the metrics
--          `action` field (platform/shared/policy/metrics.go uses
--          GetActionForPhase raw). This migration makes the phase columns match
--          the relaxed base `action`.
-- Related: #2702, #2696. ADR-036 (Governance Profiles); migrations 066/067.
--
-- SCOPE: system-tier `security-sqli` rows whose base `action` is 'warn' but whose
-- phase columns still read 'block'. Intentionally NOT touched:
--   * PII (`pii-*`)            — phase columns are already warn/log/redact
--                               (detect-then-redact); aligning them to base would
--                               wrongly drop the response-phase 'redact'.
--   * `security-dangerous` / `pii-indonesia` — base AND phase are legitimately
--                               'block' (these genuinely block by default).
--
-- NO ENFORCEMENT BEHAVIOR CHANGE: the profile override already wins, so the
-- runtime SQLi action is 'warn' in the `default` profile before and after. This
-- only corrects the stored / API-displayed / metrics value.
-- IDEMPOTENT: the WHERE matches nothing on re-run.

UPDATE static_policies
SET action_request  = action,
    action_response = action,
    updated_at      = NOW()
WHERE tier = 'system'
  AND category IN ('security-sqli', 'sqli')
  AND action = 'warn'
  AND (action_request = 'block' OR action_response = 'block');

-- Fail-loud verification: no security-sqli system row should still carry a
-- 'block' phase action after this migration.
DO $$
DECLARE
    stale_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO stale_count
    FROM static_policies
    WHERE tier = 'system'
      AND category IN ('security-sqli', 'sqli')
      AND action = 'warn'
      AND (action_request = 'block' OR action_response = 'block');
    IF stale_count > 0 THEN
        RAISE WARNING 'Migration 124: % security-sqli system rows still have a block phase action', stale_count;
    ELSE
        RAISE NOTICE 'Migration 124 verified: security-sqli phase actions aligned with base action (warn)';
    END IF;
END $$;
