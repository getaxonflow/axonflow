-- Migration 011: Audit Logs
-- Date: 2025-11-20
-- Purpose: Add audit logging tables for agent and orchestrator
-- Source: platform/agent/init_db.sql and platform/database/dynamic_policy_schema.sql
-- Related: Issue #19 - AWS Marketplace schema consistency

-- =============================================================================
-- Agent Audit Logs Table
-- =============================================================================
-- Tracks all agent actions for compliance and debugging
CREATE TABLE IF NOT EXISTS agent_audit_logs (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(255), -- Multi-tenant isolation column for RLS
    client_id VARCHAR(100),
    action VARCHAR(100),
    resource TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Agent audit logs indexes
CREATE INDEX IF NOT EXISTS idx_agent_audit_logs_client ON agent_audit_logs(client_id);
CREATE INDEX IF NOT EXISTS idx_agent_audit_logs_timestamp ON agent_audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_agent_audit_logs_action ON agent_audit_logs(action);

-- =============================================================================
-- Orchestrator Audit Logs Table
-- =============================================================================
-- Tracks all orchestrator actions for compliance and debugging
CREATE TABLE IF NOT EXISTS orchestrator_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    org_id VARCHAR(255), -- Multi-tenant isolation column for RLS
    service_id VARCHAR(100) NOT NULL,
    action VARCHAR(255) NOT NULL,
    resource TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Fix legacy schema: add missing columns if needed (handles production database)
DO $$
BEGIN
    -- Check if legacy table exists with old schema (has workflow_id but not service_id)
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'orchestrator_audit_logs' AND column_name = 'workflow_id'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'orchestrator_audit_logs' AND column_name = 'service_id'
    ) THEN
        -- Add missing columns for new schema
        ALTER TABLE orchestrator_audit_logs ADD COLUMN IF NOT EXISTS service_id VARCHAR(100);
        ALTER TABLE orchestrator_audit_logs ADD COLUMN IF NOT EXISTS action VARCHAR(255);
        ALTER TABLE orchestrator_audit_logs ADD COLUMN IF NOT EXISTS resource TEXT;
        RAISE NOTICE 'Added service_id, action, resource columns to orchestrator_audit_logs for schema consistency';
    END IF;
END $$;

-- Orchestrator audit logs indexes (now safe to create with service_id)
CREATE INDEX IF NOT EXISTS idx_orchestrator_audit_logs_service ON orchestrator_audit_logs(service_id);
CREATE INDEX IF NOT EXISTS idx_orchestrator_audit_logs_timestamp ON orchestrator_audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_orchestrator_audit_logs_action ON orchestrator_audit_logs(action);

-- Migration complete
-- Next: Test with empty database
