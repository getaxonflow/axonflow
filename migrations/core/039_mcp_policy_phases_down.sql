-- Rollback Migration 039: MCP Policy Phases
-- This removes all schema changes from migration 039

-- Drop RLS policy
DROP POLICY IF EXISTS policy_evaluations_tenant_isolation ON policy_evaluations;

-- Disable RLS
ALTER TABLE policy_evaluations DISABLE ROW LEVEL SECURITY;

-- Drop policy_evaluations table and indexes
DROP INDEX IF EXISTS idx_policy_evaluations_recent;
DROP INDEX IF EXISTS idx_policy_evaluations_performance;
DROP INDEX IF EXISTS idx_policy_evaluations_blocked;
DROP INDEX IF EXISTS idx_policy_evaluations_tenant_time;
DROP TABLE IF EXISTS policy_evaluations;

-- Drop indexes on static_policies
DROP INDEX IF EXISTS idx_static_policies_mcp_eval;
DROP INDEX IF EXISTS idx_static_policies_response_phase;
DROP INDEX IF EXISTS idx_static_policies_request_phase;

-- Drop constraints (must be done before dropping columns)
ALTER TABLE static_policies DROP CONSTRAINT IF EXISTS static_policies_action_response_check;
ALTER TABLE static_policies DROP CONSTRAINT IF EXISTS static_policies_action_request_check;
ALTER TABLE static_policies DROP CONSTRAINT IF EXISTS static_policies_phase_check;

-- Drop columns from static_policies
ALTER TABLE static_policies DROP COLUMN IF EXISTS action_response;
ALTER TABLE static_policies DROP COLUMN IF EXISTS action_request;
ALTER TABLE static_policies DROP COLUMN IF EXISTS phase;
