-- Migration 177 DOWN: return the six sensitive-data system policies' phase
-- actions to NULL, and restore core/120's table comment.
-- Date: 2026-09-10
-- Issue: #3961
--
-- Scope mirrors the up migration: the six core/035 system rows, and only a
-- phase column that still holds the 'warn' the up migration wrote. A phase
-- column an operator has since changed to something else is left alone.
--
-- On a v11 binary this makes those rows resolve through GetActionForPhase's
-- category fallback ('log') again, which is why the up migration exists; roll
-- it back only together with the code that made the stored action decide.

BEGIN;

UPDATE static_policies
SET action_request = NULL,
    updated_at     = NOW()
WHERE tier = 'system'
  AND category = 'sensitive-data'
  AND policy_id IN ('sys_sensitive_password', 'sys_sensitive_api_key', 'sys_sensitive_token',
                    'sys_sensitive_secret', 'sys_sensitive_credentials', 'sys_sensitive_connection')
  AND action_request = 'warn';

UPDATE static_policies
SET action_response = NULL,
    updated_at      = NOW()
WHERE tier = 'system'
  AND category = 'sensitive-data'
  AND policy_id IN ('sys_sensitive_password', 'sys_sensitive_api_key', 'sys_sensitive_token',
                    'sys_sensitive_secret', 'sys_sensitive_credentials', 'sys_sensitive_connection')
  AND action_response = 'warn';

COMMENT ON TABLE detection_action_overrides IS
    'Per-(org, category) detection-action override. Consulted (short-TTL cached) by the agent MCP + gateway check paths; falls back to the deployment-global env config (PII_ACTION etc) when absent. #2581.';

COMMIT;
