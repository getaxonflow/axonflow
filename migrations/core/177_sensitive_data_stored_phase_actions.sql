-- Migration 177: give the six sensitive-data system policies a STORED phase action
-- Date: 2026-09-10
-- Issue: #3961 (the four detection env vars stop setting actions; the stored
--        policy action decides)
--
-- WHY ---------------------------------------------------------------------
-- core/035 seeded the six sys_sensitive_* rows with action = 'warn' and left
-- action_request / action_response NULL. Until v11 that did not matter, because
-- the stored action never ran on those planes: EvalOptions.ActionOverrides
-- replaced it with the deployment's SENSITIVE_DATA_ACTION, whose default under
-- the v10 `default` governance profile was 'warn'
-- (platform/agent/profile.go, ProfileDefaults(ProfileDefault).SensitiveDataAction,
-- at 6d75d0e60).
--
-- #3961 removes that environment variable and the profile's action matrix: the
-- stored policy action decides, and only an organization's recorded override
-- may replace it - and the override table has no sensitive-data category, so
-- for these six rows nothing ever does. With NULL phase columns the shared
-- engine would resolve GetActionForPhase's category/severity FALLBACK, which is
-- 'log' for sensitive-data: a silent weakening from 'warn' that no policy
-- author ever chose, and a "stored action" that is not stored anywhere.
--
-- So this migration makes the action every deployment ran with before v11 an
-- explicit, stored fact of the row: 'warn' on both phases, equal to the row's
-- own base `action`. It changes no enforced action on an upgrade from the
-- default posture, and it is the first time these rows' phase columns say what
-- runs.
--
-- It also re-issues the COMMENT on detection_action_overrides (core/120), which
-- is stored in the database and still described the removed fallback to
-- "the deployment-global env config (PII_ACTION etc)".
--
-- SCOPE: exactly the six core/035 system rows, and only a phase column that is
-- still NULL, so an operator who has already set one is not overwritten.
-- IDEMPOTENT: the WHERE matches nothing on a re-run.

BEGIN;

UPDATE static_policies
SET action_request = 'warn',
    updated_at     = NOW()
WHERE tier = 'system'
  AND category = 'sensitive-data'
  AND policy_id IN ('sys_sensitive_password', 'sys_sensitive_api_key', 'sys_sensitive_token',
                    'sys_sensitive_secret', 'sys_sensitive_credentials', 'sys_sensitive_connection')
  AND action_request IS NULL;

UPDATE static_policies
SET action_response = 'warn',
    updated_at      = NOW()
WHERE tier = 'system'
  AND category = 'sensitive-data'
  AND policy_id IN ('sys_sensitive_password', 'sys_sensitive_api_key', 'sys_sensitive_token',
                    'sys_sensitive_secret', 'sys_sensitive_credentials', 'sys_sensitive_connection')
  AND action_response IS NULL;

COMMENT ON TABLE detection_action_overrides IS
    'Per-(org, category) detection-action override. Consulted (short-TTL cached) by the agent MCP + gateway check paths and the orchestrator response plane; the ONLY thing that may replace a policy''s stored action (#3961). A category with no row keeps the stored policy action. #2581.';

-- Verification - fail loudly (Principle 3). Bound to the same condition the
-- updates use: the six rows exist, and none still has a NULL phase column.
DO $$
DECLARE
    present   INTEGER;
    still_null INTEGER;
BEGIN
    SELECT COUNT(*),
           COUNT(*) FILTER (WHERE action_request IS NULL OR action_response IS NULL)
      INTO present, still_null
      FROM static_policies
     WHERE tier = 'system'
       AND category = 'sensitive-data'
       AND policy_id IN ('sys_sensitive_password', 'sys_sensitive_api_key', 'sys_sensitive_token',
                         'sys_sensitive_secret', 'sys_sensitive_credentials', 'sys_sensitive_connection');
    IF present <> 6 THEN
        RAISE EXCEPTION 'Migration 177 failed: expected the 6 core/035 sensitive-data system policies, found %', present;
    END IF;
    IF still_null <> 0 THEN
        RAISE EXCEPTION 'Migration 177 failed: % sensitive-data system policies still have a NULL phase action', still_null;
    END IF;
    RAISE NOTICE 'Migration 177 verified: 6 sensitive-data system policies carry stored phase actions';
END
$$;

COMMIT;
