-- Copyright 2025 AxonFlow
-- Licensed under the Apache License, Version 2.0

-- =============================================================================
-- Rollback: Decision Chain Tracing
-- =============================================================================

-- Drop views
DROP VIEW IF EXISTS decision_chain_metrics;
DROP VIEW IF EXISTS recent_decision_chains;

-- Drop functions
DROP FUNCTION IF EXISTS cleanup_expired_decision_chains();
DROP FUNCTION IF EXISTS get_chain_summary(UUID);
DROP FUNCTION IF EXISTS chain_has_blocked_decision(UUID);
DROP FUNCTION IF EXISTS get_chain_total_processing_time(UUID);
DROP FUNCTION IF EXISTS get_decision_chain(UUID);

-- Drop RLS policy
DROP POLICY IF EXISTS decision_chain_org_isolation ON decision_chain;

-- Drop table (will cascade indexes)
DROP TABLE IF EXISTS decision_chain;
