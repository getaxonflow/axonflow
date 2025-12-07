-- Copyright 2025 AxonFlow
-- Licensed under the Apache License, Version 2.0

-- =============================================================================
-- Decision Chain Tracing (EU AI Act Article 12 - Record-keeping)
-- =============================================================================
--
-- This migration creates infrastructure for tracing AI decision chains.
-- A decision chain links related AI decisions across multiple requests in
-- a multi-step workflow, enabling full traceability for audit purposes.
--
-- EU AI Act Requirements Addressed:
--   - Article 12: Automatic recording of events (logs)
--   - Article 12: Traceability of AI system functioning
--   - Article 13: Transparency in decision-making process
--
-- Example: A travel booking workflow might have these linked decisions:
--   1. Search flights (chain_id: abc123, step: 1)
--   2. Apply PII policies (chain_id: abc123, step: 2)
--   3. Generate response (chain_id: abc123, step: 3)
--
-- =============================================================================

-- Decision chain entries table
-- Stores individual decision steps within a chain
CREATE TABLE IF NOT EXISTS decision_chain (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Chain identification
    chain_id UUID NOT NULL,              -- Links related decisions together
    request_id UUID NOT NULL,            -- Unique ID for this specific request
    parent_request_id UUID,              -- Previous request in chain (NULL for first)
    step_number INTEGER NOT NULL DEFAULT 1,  -- Order within the chain

    -- Tenant context
    org_id UUID NOT NULL,
    tenant_id TEXT NOT NULL,
    client_id TEXT,
    user_id TEXT,

    -- Decision details
    decision_type TEXT NOT NULL CHECK (decision_type IN (
        'policy_enforcement',    -- Static policy check
        'llm_generation',        -- LLM model invocation
        'data_retrieval',        -- Connector/data source query
        'human_review',          -- HITL decision
        'system_action'          -- Automated system action
    )),

    -- AI system information
    system_id TEXT NOT NULL,             -- e.g., "axonflow-agent/1.0.0"
    model_provider TEXT,                 -- LLM provider (if applicable)
    model_id TEXT,                       -- Specific model version

    -- Decision outcome
    decision_outcome TEXT NOT NULL CHECK (decision_outcome IN (
        'approved',              -- Request allowed to proceed
        'blocked',               -- Request denied by policy
        'modified',              -- Content was filtered/modified
        'pending_review',        -- Awaiting human review
        'error'                  -- Processing error occurred
    )),

    -- Policy information
    policies_evaluated TEXT[] DEFAULT '{}',  -- List of policy IDs evaluated
    policy_triggered TEXT,                   -- Policy that caused block/modify (if any)

    -- Risk assessment
    risk_level TEXT DEFAULT 'limited' CHECK (risk_level IN (
        'minimal', 'limited', 'high', 'unacceptable'
    )),
    requires_human_review BOOLEAN DEFAULT FALSE,

    -- Performance metrics
    processing_time_ms INTEGER,

    -- Context and metadata
    input_hash TEXT,                     -- SHA-256 of input (for deduplication)
    output_hash TEXT,                    -- SHA-256 of output (for verification)
    data_sources TEXT[] DEFAULT '{}',    -- Data sources queried
    metadata JSONB DEFAULT '{}',         -- Additional context

    -- Audit trail
    audit_hash TEXT,                     -- SHA-256 hash for tamper detection
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Indexes for efficient querying
    CONSTRAINT fk_decision_chain_org FOREIGN KEY (org_id)
        REFERENCES organizations(id) ON DELETE CASCADE
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_decision_chain_chain_id
    ON decision_chain(chain_id);

CREATE INDEX IF NOT EXISTS idx_decision_chain_request_id
    ON decision_chain(request_id);

CREATE INDEX IF NOT EXISTS idx_decision_chain_org_tenant
    ON decision_chain(org_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_decision_chain_created_at
    ON decision_chain(created_at);

CREATE INDEX IF NOT EXISTS idx_decision_chain_decision_type
    ON decision_chain(decision_type);

CREATE INDEX IF NOT EXISTS idx_decision_chain_decision_outcome
    ON decision_chain(decision_outcome);

-- Composite index for chain traversal
CREATE INDEX IF NOT EXISTS idx_decision_chain_chain_step
    ON decision_chain(chain_id, step_number);

-- Index for finding chains by date range (for retention policies)
CREATE INDEX IF NOT EXISTS idx_decision_chain_org_created
    ON decision_chain(org_id, created_at DESC);

-- Partial index for pending reviews
CREATE INDEX IF NOT EXISTS idx_decision_chain_pending_review
    ON decision_chain(org_id, created_at)
    WHERE requires_human_review = TRUE;

-- =============================================================================
-- Row Level Security
-- =============================================================================

ALTER TABLE decision_chain ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see decision chains for their organization
-- Uses the get_current_org_id() helper function from 018_row_level_security.sql
CREATE POLICY decision_chain_org_isolation ON decision_chain
    FOR ALL
    USING (org_id = get_current_org_id());

-- =============================================================================
-- Helper Functions
-- =============================================================================

-- Function to get a complete decision chain by chain_id
-- Returns all steps ordered by step_number
CREATE OR REPLACE FUNCTION get_decision_chain(p_chain_id UUID)
RETURNS TABLE (
    id UUID,
    chain_id UUID,
    request_id UUID,
    step_number INTEGER,
    decision_type TEXT,
    decision_outcome TEXT,
    policies_evaluated TEXT[],
    risk_level TEXT,
    processing_time_ms INTEGER,
    created_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        dc.id,
        dc.chain_id,
        dc.request_id,
        dc.step_number,
        dc.decision_type,
        dc.decision_outcome,
        dc.policies_evaluated,
        dc.risk_level,
        dc.processing_time_ms,
        dc.created_at
    FROM decision_chain dc
    WHERE dc.chain_id = p_chain_id
    ORDER BY dc.step_number ASC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get the total processing time for a chain
CREATE OR REPLACE FUNCTION get_chain_total_processing_time(p_chain_id UUID)
RETURNS INTEGER AS $$
DECLARE
    total_ms INTEGER;
BEGIN
    SELECT COALESCE(SUM(processing_time_ms), 0)
    INTO total_ms
    FROM decision_chain
    WHERE chain_id = p_chain_id;

    RETURN total_ms;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to check if a chain has any blocked decisions
CREATE OR REPLACE FUNCTION chain_has_blocked_decision(p_chain_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    has_blocked BOOLEAN;
BEGIN
    SELECT EXISTS(
        SELECT 1 FROM decision_chain
        WHERE chain_id = p_chain_id
        AND decision_outcome = 'blocked'
    ) INTO has_blocked;

    RETURN has_blocked;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get chain summary statistics
CREATE OR REPLACE FUNCTION get_chain_summary(p_chain_id UUID)
RETURNS TABLE (
    chain_id UUID,
    total_steps INTEGER,
    total_processing_time_ms INTEGER,
    has_blocked BOOLEAN,
    requires_review BOOLEAN,
    highest_risk_level TEXT,
    first_decision_at TIMESTAMPTZ,
    last_decision_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        p_chain_id,
        COUNT(*)::INTEGER as total_steps,
        COALESCE(SUM(dc.processing_time_ms), 0)::INTEGER as total_processing_time_ms,
        bool_or(dc.decision_outcome = 'blocked') as has_blocked,
        bool_or(dc.requires_human_review) as requires_review,
        CASE
            WHEN bool_or(dc.risk_level = 'unacceptable') THEN 'unacceptable'
            WHEN bool_or(dc.risk_level = 'high') THEN 'high'
            WHEN bool_or(dc.risk_level = 'limited') THEN 'limited'
            ELSE 'minimal'
        END as highest_risk_level,
        MIN(dc.created_at) as first_decision_at,
        MAX(dc.created_at) as last_decision_at
    FROM decision_chain dc
    WHERE dc.chain_id = p_chain_id
    GROUP BY p_chain_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- Views for Common Queries
-- =============================================================================

-- View: Recent decision chains with summary (last 24 hours)
CREATE OR REPLACE VIEW recent_decision_chains AS
SELECT
    dc.chain_id,
    dc.org_id,
    dc.tenant_id,
    COUNT(*) as step_count,
    COALESCE(SUM(dc.processing_time_ms), 0) as total_processing_time_ms,
    bool_or(dc.decision_outcome = 'blocked') as has_blocked,
    bool_or(dc.requires_human_review) as requires_review,
    array_agg(DISTINCT dc.decision_type) as decision_types,
    MIN(dc.created_at) as started_at,
    MAX(dc.created_at) as completed_at
FROM decision_chain dc
WHERE dc.created_at > NOW() - INTERVAL '24 hours'
GROUP BY dc.chain_id, dc.org_id, dc.tenant_id
ORDER BY MIN(dc.created_at) DESC;

-- View: Decision chain metrics by tenant
CREATE OR REPLACE VIEW decision_chain_metrics AS
SELECT
    dc.org_id,
    dc.tenant_id,
    DATE(dc.created_at) as date,
    COUNT(DISTINCT dc.chain_id) as unique_chains,
    COUNT(*) as total_decisions,
    COUNT(*) FILTER (WHERE dc.decision_outcome = 'blocked') as blocked_count,
    COUNT(*) FILTER (WHERE dc.decision_outcome = 'modified') as modified_count,
    COUNT(*) FILTER (WHERE dc.requires_human_review) as review_required_count,
    AVG(dc.processing_time_ms)::INTEGER as avg_processing_time_ms,
    MAX(dc.processing_time_ms) as max_processing_time_ms
FROM decision_chain dc
WHERE dc.created_at > NOW() - INTERVAL '30 days'
GROUP BY dc.org_id, dc.tenant_id, DATE(dc.created_at)
ORDER BY date DESC;

-- =============================================================================
-- Retention Policy Support
-- =============================================================================

-- Function to delete old decision chains based on retention policy
-- This respects the retention configuration set per-org
CREATE OR REPLACE FUNCTION cleanup_expired_decision_chains()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER := 0;
    r RECORD;
BEGIN
    -- Delete decision chains older than the configured retention period
    -- Default to 7 years if no retention config exists (EU AI Act minimum)
    FOR r IN
        SELECT DISTINCT dc.org_id,
               COALESCE(
                   (SELECT arc.retention_days
                    FROM audit_retention_config arc
                    WHERE arc.org_id = dc.org_id
                    AND arc.data_type = 'decision_chain'
                    AND arc.is_active = TRUE),
                   2555  -- 7 years default (EU AI Act minimum)
               ) as retention_days
        FROM decision_chain dc
    LOOP
        DELETE FROM decision_chain
        WHERE org_id = r.org_id
        AND created_at < NOW() - (r.retention_days || ' days')::INTERVAL;

        deleted_count := deleted_count + ROW_COUNT;
    END LOOP;

    IF deleted_count > 0 THEN
        RAISE NOTICE 'Cleaned up % expired decision chain entries', deleted_count;
    END IF;

    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Comments for Documentation
-- =============================================================================

COMMENT ON TABLE decision_chain IS
'Stores AI decision chain entries for EU AI Act Article 12 compliance.
Each entry represents a single decision step in a multi-step AI workflow.
Related decisions share the same chain_id for complete traceability.';

COMMENT ON COLUMN decision_chain.chain_id IS
'UUID linking related decisions in a multi-step workflow.
Generated at the start of a workflow and propagated to all subsequent steps.';

COMMENT ON COLUMN decision_chain.step_number IS
'Order of this decision within the chain. Starts at 1 and increments.';

COMMENT ON COLUMN decision_chain.audit_hash IS
'SHA-256 hash of decision data for tamper detection.
Enables verification that audit records have not been modified.';

COMMENT ON COLUMN decision_chain.risk_level IS
'EU AI Act risk classification for this decision:
minimal (no significant risk), limited (transparency obligations),
high (requires conformity assessment), unacceptable (prohibited).';

COMMENT ON FUNCTION get_decision_chain(UUID) IS
'Retrieves all steps in a decision chain ordered by step number.
Use this to reconstruct the full decision trail for a workflow.';

COMMENT ON FUNCTION get_chain_summary(UUID) IS
'Returns aggregate statistics for a decision chain including
total steps, processing time, and risk assessment.';
