-- Migration: 042_unified_execution_history.sql
-- Description: Unified execution history for MAP and WCP (ADR-030)
-- EPIC: #1074 - Unified Workflow Infrastructure
-- Issue: #1075 - Unified ExecutionStatus schema

-- ============================================================================
-- Unified Execution History Table
-- ============================================================================
-- Stores execution history for both:
-- - MAP (Multi-Agent Planning) plans
-- - WCP (Workflow Control Plane) external workflows
--
-- Benefits:
-- - Single schema for consistent status tracking
-- - Unified Portal and SDK types
-- - Compliance-grade execution audit trail
-- - Cost tracking per execution and step

CREATE TABLE IF NOT EXISTS execution_history (
    -- Primary key
    id VARCHAR(255) PRIMARY KEY,

    -- Execution type discriminator
    execution_type VARCHAR(20) NOT NULL CHECK (execution_type IN ('map_plan', 'wcp_workflow')),

    -- External reference (plan_id for MAP, workflow_id for WCP)
    external_id VARCHAR(255) NOT NULL,

    -- Human-readable name
    name VARCHAR(500) NOT NULL,

    -- Source (for WCP: langchain, crewai, external; for MAP: null)
    source VARCHAR(50),

    -- Multi-tenancy (using VARCHAR to match organizations.org_id)
    tenant_id VARCHAR(255) REFERENCES organizations(org_id),
    org_id VARCHAR(255),
    user_id VARCHAR(255),
    client_id VARCHAR(255),

    -- Status tracking
    status VARCHAR(50) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled', 'aborted', 'expired')),
    current_step_index INTEGER NOT NULL DEFAULT 0,
    total_steps INTEGER NOT NULL DEFAULT 0,

    -- Timing
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Cost tracking
    estimated_cost_usd DECIMAL(10,6),
    actual_cost_usd DECIMAL(10,6),

    -- Steps array (JSONB for flexibility)
    -- Each step contains: step_id, step_index, step_name, step_type, status,
    --                     started_at, ended_at, decision, policies_matched,
    --                     approval_status, cost_usd, result_summary, error
    steps JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- Result storage (for completed executions)
    result JSONB,

    -- Error message (for failed/cancelled executions)
    error_message TEXT,

    -- Arbitrary metadata
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Indexes
-- ============================================================================

-- Primary lookup patterns
CREATE INDEX idx_execution_history_tenant ON execution_history(tenant_id);
CREATE INDEX idx_execution_history_type ON execution_history(execution_type);
CREATE INDEX idx_execution_history_status ON execution_history(status);
CREATE INDEX idx_execution_history_external ON execution_history(external_id);

-- Time-based queries (most recent first)
CREATE INDEX idx_execution_history_created ON execution_history(created_at DESC);
CREATE INDEX idx_execution_history_started ON execution_history(started_at DESC);

-- Composite indexes for common queries
CREATE INDEX idx_execution_history_tenant_type ON execution_history(tenant_id, execution_type);
CREATE INDEX idx_execution_history_tenant_status ON execution_history(tenant_id, status);
CREATE INDEX idx_execution_history_type_status ON execution_history(execution_type, status);

-- JSONB index for step queries (GIN index)
CREATE INDEX idx_execution_history_steps ON execution_history USING GIN (steps);

-- ============================================================================
-- Row-Level Security
-- ============================================================================

ALTER TABLE execution_history ENABLE ROW LEVEL SECURITY;

-- Tenant isolation policy
CREATE POLICY execution_history_tenant_isolation ON execution_history
    FOR ALL
    USING (
        tenant_id IS NULL OR
        tenant_id::text = COALESCE(current_setting('app.current_tenant_id', true), '')
    );

-- ============================================================================
-- Trigger for updated_at
-- ============================================================================

CREATE OR REPLACE FUNCTION update_execution_history_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_execution_history_updated_at
    BEFORE UPDATE ON execution_history
    FOR EACH ROW
    EXECUTE FUNCTION update_execution_history_updated_at();

-- ============================================================================
-- Cleanup Function for Expired Executions
-- ============================================================================

CREATE OR REPLACE FUNCTION cleanup_old_execution_history(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM execution_history
    WHERE created_at < CURRENT_TIMESTAMP - (retention_days || ' days')::interval
    AND status IN ('completed', 'failed', 'cancelled', 'aborted', 'expired');

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Helper View: Active Executions
-- ============================================================================

CREATE OR REPLACE VIEW active_executions AS
SELECT
    id,
    execution_type,
    name,
    source,
    tenant_id,
    status,
    current_step_index,
    total_steps,
    CASE
        WHEN total_steps > 0 THEN
            ROUND((current_step_index::decimal / total_steps) * 100, 1)
        ELSE 0
    END as progress_percent,
    started_at,
    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - started_at)) as duration_seconds,
    estimated_cost_usd,
    actual_cost_usd,
    jsonb_array_length(steps) as step_count,
    created_at
FROM execution_history
WHERE status IN ('pending', 'running');

-- ============================================================================
-- Comments for documentation
-- ============================================================================

COMMENT ON TABLE execution_history IS 'Unified execution tracking for MAP plans and WCP workflows (ADR-030)';
COMMENT ON COLUMN execution_history.execution_type IS 'Discriminator: map_plan or wcp_workflow';
COMMENT ON COLUMN execution_history.external_id IS 'Original ID from source system (plan_id or workflow_id)';
COMMENT ON COLUMN execution_history.steps IS 'JSON array of step status objects with full execution details';
COMMENT ON COLUMN execution_history.source IS 'For WCP: external orchestrator type (langchain, crewai, etc.)';
