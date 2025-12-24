-- Migration 030a Down: Revert action_override CHECK constraint fix
-- This restores the original constraint without 'redact'

ALTER TABLE policy_overrides
    DROP CONSTRAINT IF EXISTS policy_overrides_action_override_check;

ALTER TABLE policy_overrides
    ADD CONSTRAINT policy_overrides_action_override_check
    CHECK (action_override IN ('block', 'warn', 'log'));

COMMENT ON COLUMN policy_overrides.action_override IS 'Override action: block, warn, or log';
