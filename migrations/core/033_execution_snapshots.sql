-- Copyright 2025 AxonFlow
-- SPDX-License-Identifier: BUSL-1.1
--
-- Migration: 033_execution_snapshots
-- Description: Add execution snapshots for replay/debug mode (#763)
-- Phase 1: Data capture and API

-- Execution snapshots table - captures each step of workflow execution
CREATE TABLE IF NOT EXISTS execution_snapshots (
    id SERIAL PRIMARY KEY,
    request_id VARCHAR(255) NOT NULL,
    step_index INTEGER NOT NULL,
    step_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,  -- pending, running, completed, failed, paused

    -- Timing
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_ms INTEGER,

    -- Input/Output (JSONB for flexibility)
    input JSONB,
    output JSONB,

    -- LLM Details
    provider VARCHAR(100),
    model VARCHAR(100),
    tokens_in INTEGER DEFAULT 0,
    tokens_out INTEGER DEFAULT 0,
    cost_usd DECIMAL(10, 6) DEFAULT 0,

    -- Policy Events
    policies_checked JSONB DEFAULT '[]',
    policies_triggered JSONB DEFAULT '[]',

    -- Error info
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Ensure unique step per execution
    UNIQUE(request_id, step_index)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_snapshots_request ON execution_snapshots(request_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_status ON execution_snapshots(status);
CREATE INDEX IF NOT EXISTS idx_snapshots_created ON execution_snapshots(created_at);

-- Execution summary table - aggregates execution metadata
CREATE TABLE IF NOT EXISTS execution_summaries (
    request_id VARCHAR(255) PRIMARY KEY,
    workflow_name VARCHAR(255),
    status VARCHAR(50) NOT NULL,  -- pending, running, completed, failed
    total_steps INTEGER NOT NULL,
    completed_steps INTEGER DEFAULT 0,

    -- Timing
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_ms INTEGER,

    -- Aggregated metrics
    total_tokens INTEGER DEFAULT 0,
    total_cost_usd DECIMAL(10, 6) DEFAULT 0,

    -- Context for multi-tenancy
    org_id VARCHAR(255),
    tenant_id VARCHAR(255),
    user_id VARCHAR(255),
    agent_id VARCHAR(255),

    -- Metadata
    input_summary JSONB,
    output_summary JSONB,
    error_message TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_summaries_org ON execution_summaries(org_id);
CREATE INDEX IF NOT EXISTS idx_summaries_tenant ON execution_summaries(tenant_id);
CREATE INDEX IF NOT EXISTS idx_summaries_status ON execution_summaries(status);
CREATE INDEX IF NOT EXISTS idx_summaries_created ON execution_summaries(created_at);
CREATE INDEX IF NOT EXISTS idx_summaries_workflow ON execution_summaries(workflow_name);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_execution_summary_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update timestamp
DROP TRIGGER IF EXISTS trigger_update_execution_summary_timestamp ON execution_summaries;
CREATE TRIGGER trigger_update_execution_summary_timestamp
    BEFORE UPDATE ON execution_summaries
    FOR EACH ROW
    EXECUTE FUNCTION update_execution_summary_timestamp();

-- Comments for documentation
COMMENT ON TABLE execution_snapshots IS 'Stores step-by-step snapshots of workflow executions for replay and debugging';
COMMENT ON TABLE execution_summaries IS 'Stores summary information for completed workflow executions';
COMMENT ON COLUMN execution_snapshots.policies_checked IS 'Array of policy IDs that were evaluated for this step';
COMMENT ON COLUMN execution_snapshots.policies_triggered IS 'Array of policy events (policy_id, action, matched, resolution)';
