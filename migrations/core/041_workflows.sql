-- Copyright 2026 AxonFlow
-- SPDX-License-Identifier: BUSL-1.1
--
-- Migration: 041_workflows
-- Description: Add workflows and workflow_steps tables for Workflow Control Plane V1
-- Related: Issue #834 - Workflow Control Plane for external orchestrators (LangChain/LangGraph/CrewAI)
--
-- Design:
-- - External orchestrators register workflows with AxonFlow
-- - Before each step, orchestrators call step gate API for policy approval
-- - AxonFlow tracks all step decisions and provides governance

-- Workflows table - tracks external workflow registrations
CREATE TABLE IF NOT EXISTS workflows (
    workflow_id VARCHAR(255) PRIMARY KEY,
    workflow_name VARCHAR(255) NOT NULL,
    source VARCHAR(100) NOT NULL DEFAULT 'external',  -- langgraph, langchain, crewai, external
    status VARCHAR(50) NOT NULL DEFAULT 'in_progress',  -- in_progress, completed, aborted, failed

    -- Step tracking
    current_step_index INTEGER DEFAULT 0,
    total_steps INTEGER,

    -- Multi-tenancy
    org_id VARCHAR(255),
    tenant_id VARCHAR(255),
    user_id VARCHAR(255),
    client_id VARCHAR(255),

    -- Metadata (workflow config, tags, etc.)
    metadata JSONB DEFAULT '{}',

    -- Timestamps
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Workflow steps table - tracks gate decisions per step
CREATE TABLE IF NOT EXISTS workflow_steps (
    id SERIAL PRIMARY KEY,
    workflow_id VARCHAR(255) NOT NULL REFERENCES workflows(workflow_id) ON DELETE CASCADE,
    step_id VARCHAR(255) NOT NULL,
    step_index INTEGER NOT NULL,
    step_name VARCHAR(255),
    step_type VARCHAR(100),  -- llm_call, tool_call, connector_call, human_task

    -- Gate decision
    decision VARCHAR(50) NOT NULL,  -- allow, block, require_approval
    decision_reason TEXT,
    policies_evaluated JSONB DEFAULT '[]',
    policies_matched JSONB DEFAULT '[]',

    -- Approval workflow (if require_approval)
    approval_status VARCHAR(50),  -- null, pending, approved, rejected, expired (auto-timeout, #2654)
    approved_by VARCHAR(255),
    approved_at TIMESTAMP WITH TIME ZONE,

    -- Step context
    step_input JSONB,
    model VARCHAR(100),
    provider VARCHAR(100),

    -- Timestamps
    gate_checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    step_completed_at TIMESTAMP WITH TIME ZONE,

    -- Unique constraint per workflow
    UNIQUE(workflow_id, step_id)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflows(status);
CREATE INDEX IF NOT EXISTS idx_workflows_tenant ON workflows(tenant_id);
CREATE INDEX IF NOT EXISTS idx_workflows_org ON workflows(org_id);
CREATE INDEX IF NOT EXISTS idx_workflows_created ON workflows(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_workflows_source ON workflows(source);

-- Workflow steps indexes
CREATE INDEX IF NOT EXISTS idx_workflow_steps_workflow ON workflow_steps(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_steps_decision ON workflow_steps(decision);
CREATE INDEX IF NOT EXISTS idx_workflow_steps_pending ON workflow_steps(approval_status)
    WHERE approval_status = 'pending';

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_workflows_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update timestamp
DROP TRIGGER IF EXISTS trigger_update_workflows_timestamp ON workflows;
CREATE TRIGGER trigger_update_workflows_timestamp
    BEFORE UPDATE ON workflows
    FOR EACH ROW
    EXECUTE FUNCTION update_workflows_timestamp();

-- Comments for documentation
COMMENT ON TABLE workflows IS 'Tracks workflows registered from external orchestrators (LangChain, LangGraph, CrewAI)';
COMMENT ON TABLE workflow_steps IS 'Tracks gate decisions for each step in a workflow';
COMMENT ON COLUMN workflows.source IS 'External orchestrator: langgraph, langchain, crewai, or external';
COMMENT ON COLUMN workflows.status IS 'Workflow state: in_progress, completed, aborted, failed';
COMMENT ON COLUMN workflow_steps.decision IS 'Gate decision: allow (proceed), block (stop), require_approval (HITL)';
COMMENT ON COLUMN workflow_steps.approval_status IS 'Approval state when decision=require_approval: pending, approved, rejected, expired (auto-timeout)';

-- Log migration
DO $$
BEGIN
    RAISE NOTICE 'Migration 041: Created workflows and workflow_steps tables for Workflow Control Plane V1';
END $$;
