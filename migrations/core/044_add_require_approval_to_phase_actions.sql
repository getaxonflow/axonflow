-- Migration 044: Add require_approval to phase-specific action constraints
-- Date: 2026-01-25
-- Purpose: Allow HITL (require_approval) action in request/response phase columns
-- Related: Issue #1081, Issue #1089 (HITL Runtime Integration)
--
-- This migration fixes an oversight in migration 039 where the action_request
-- and action_response constraints were created without the 'require_approval'
-- action that was added in migration 032.

-- =============================================================================
-- PHASE 1: Update action_request constraint to include require_approval
-- =============================================================================

-- Drop the existing constraint
ALTER TABLE static_policies DROP CONSTRAINT IF EXISTS static_policies_action_request_check;

-- Add updated constraint with require_approval
ALTER TABLE static_policies ADD CONSTRAINT static_policies_action_request_check
    CHECK (action_request IS NULL OR action_request IN ('block', 'allow', 'log', 'warn', 'require_approval'));

-- =============================================================================
-- PHASE 2: Update action_response constraint to include require_approval
-- =============================================================================

-- Drop the existing constraint
ALTER TABLE static_policies DROP CONSTRAINT IF EXISTS static_policies_action_response_check;

-- Add updated constraint with require_approval (also add redact for consistency)
ALTER TABLE static_policies ADD CONSTRAINT static_policies_action_response_check
    CHECK (action_response IS NULL OR action_response IN ('block', 'redact', 'allow', 'log', 'warn', 'require_approval'));

-- =============================================================================
-- Documentation
-- =============================================================================

COMMENT ON CONSTRAINT static_policies_action_request_check ON static_policies IS
    'Valid actions for request phase: block, allow, log, warn, require_approval. require_approval triggers HITL queue.';

COMMENT ON CONSTRAINT static_policies_action_response_check ON static_policies IS
    'Valid actions for response phase: block, redact, allow, log, warn, require_approval. require_approval triggers HITL queue.';

-- =============================================================================
-- Migration complete
-- =============================================================================
--
-- This migration ensures that HITL policies created via the Static Policy API
-- can use require_approval as the action for both request and response phases.
