-- Migration 044 Down: Revert action constraints to exclude require_approval
-- This restores the original constraints from migration 039

-- Revert action_request constraint
ALTER TABLE static_policies DROP CONSTRAINT IF EXISTS static_policies_action_request_check;
ALTER TABLE static_policies ADD CONSTRAINT static_policies_action_request_check
    CHECK (action_request IS NULL OR action_request IN ('block', 'allow', 'log', 'warn'));

-- Revert action_response constraint
ALTER TABLE static_policies DROP CONSTRAINT IF EXISTS static_policies_action_response_check;
ALTER TABLE static_policies ADD CONSTRAINT static_policies_action_response_check
    CHECK (action_response IS NULL OR action_response IN ('block', 'redact', 'allow', 'log', 'warn'));
