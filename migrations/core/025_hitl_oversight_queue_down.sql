-- Migration 025 DOWN: Remove HITL Oversight Queue
-- Date: 2025-12-07
-- Purpose: Rollback EU AI Act Article 14 HITL infrastructure

-- Drop views first (depend on tables)
DROP VIEW IF EXISTS eu_ai_act_hitl_metrics;
DROP VIEW IF EXISTS hitl_pending_summary;

-- Drop triggers
DROP TRIGGER IF EXISTS update_hitl_queue_updated_at ON hitl_approval_queue;

-- Drop functions
DROP FUNCTION IF EXISTS get_hitl_pending_count(VARCHAR);
DROP FUNCTION IF EXISTS expire_hitl_requests();

-- Drop RLS policies
DROP POLICY IF EXISTS hitl_queue_tenant_isolation ON hitl_approval_queue;
DROP POLICY IF EXISTS hitl_history_tenant_isolation ON hitl_approval_history;
DROP POLICY IF EXISTS hitl_history_insert ON hitl_approval_history;
DROP POLICY IF EXISTS decision_chain_tenant_isolation ON decision_chain;

-- Drop tables (history first due to foreign key-like relationship)
DROP TABLE IF EXISTS hitl_approval_history;
DROP TABLE IF EXISTS hitl_approval_queue;
DROP TABLE IF EXISTS decision_chain;

DO $$
BEGIN
    RAISE NOTICE '✅ HITL Oversight Queue migration rolled back';
END $$;
