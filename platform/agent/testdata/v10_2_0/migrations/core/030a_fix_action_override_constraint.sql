-- Migration 030a: Fix action_override CHECK constraint
-- Date: 2025-12-24
-- Purpose: Add 'redact' to valid action_override values in policy_overrides
-- Related: ADR-020 - Unified Policy Architecture, Issue #724

-- =============================================================================
-- Fix the action_override CHECK constraint to include 'redact'
-- =============================================================================

-- Drop the existing constraint (named implicitly based on column)
ALTER TABLE policy_overrides
    DROP CONSTRAINT IF EXISTS policy_overrides_action_override_check;

-- Add the corrected constraint with 'redact' included
ALTER TABLE policy_overrides
    ADD CONSTRAINT policy_overrides_action_override_check
    CHECK (action_override IN ('block', 'redact', 'warn', 'log'));

-- Update the comment
COMMENT ON COLUMN policy_overrides.action_override IS 'Override action: block (reject), redact (mask content), warn (allow with warning), or log (audit only)';
