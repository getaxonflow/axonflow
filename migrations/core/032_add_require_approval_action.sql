-- Migration: Add require_approval action for HITL integration
-- Issue #762: HITL Integration for EU AI Act Article 14 compliance
--
-- This migration adds 'require_approval' to the valid actions for policy overrides.
-- This action pauses execution and requires human approval before proceeding.

-- First, convert any legacy 'alert' actions to 'require_approval'
-- (alert was used in EU AI Act templates before HITL was properly implemented)
UPDATE static_policies SET action = 'require_approval' WHERE action = 'alert';

-- Update the CHECK constraint on static_policies table
ALTER TABLE static_policies DROP CONSTRAINT IF EXISTS static_policies_action_check;
ALTER TABLE static_policies ADD CONSTRAINT static_policies_action_check
    CHECK (action IN ('block', 'require_approval', 'redact', 'warn', 'log'));

-- Update the CHECK constraint on policy_overrides table
ALTER TABLE policy_overrides DROP CONSTRAINT IF EXISTS policy_overrides_action_override_check;
ALTER TABLE policy_overrides ADD CONSTRAINT policy_overrides_action_override_check
    CHECK (action_override IN ('block', 'require_approval', 'redact', 'warn', 'log'));

-- Note: dynamic_policies uses 'actions' (JSONB), not 'action' (VARCHAR)
-- The actions are stored as a JSON array of action objects, so no CHECK constraint applies

COMMENT ON CONSTRAINT static_policies_action_check ON static_policies IS
    'Valid actions: block, require_approval, redact, warn, log. require_approval triggers HITL queue.';
