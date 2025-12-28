-- Down migration: Remove require_approval action
-- WARNING: This will convert require_approval actions to alternative actions.
-- Review affected policies after running this migration.

-- Convert require_approval back to alert for static policies (EU AI Act templates)
UPDATE static_policies SET action = 'alert' WHERE action = 'require_approval';

-- Convert require_approval overrides to warn (closest safe alternative)
-- Note: policy_overrides never had 'alert' in the original schema
UPDATE policy_overrides SET action_override = 'warn' WHERE action_override = 'require_approval';

-- Restore original CHECK constraint on static_policies table
ALTER TABLE static_policies DROP CONSTRAINT IF EXISTS static_policies_action_check;
ALTER TABLE static_policies ADD CONSTRAINT static_policies_action_check
    CHECK (action IN ('block', 'alert', 'redact', 'warn', 'log'));

-- Restore original CHECK constraint on policy_overrides table
-- Note: 'alert' was never a valid override action (overrides change enforcement, not alerting)
ALTER TABLE policy_overrides DROP CONSTRAINT IF EXISTS policy_overrides_action_override_check;
ALTER TABLE policy_overrides ADD CONSTRAINT policy_overrides_action_override_check
    CHECK (action_override IN ('block', 'redact', 'warn', 'log'));

-- Note: dynamic_policies uses 'actions' (JSONB), not 'action' (VARCHAR)
-- No constraint change needed
