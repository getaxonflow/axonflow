-- Migration 025: Human-in-the-Loop (HITL) Oversight Queue
-- Date: 2025-12-07
-- Purpose: EU AI Act Article 14 compliance - Human oversight workflow infrastructure
-- Related: Issue #311 - EU AI Act Complete Compliance Package
--
-- EU AI Act Article 14 Requirements:
-- - High-risk AI systems must be designed for human oversight
-- - Natural persons must be able to understand AI system capabilities
-- - Override and interrupt capabilities must be provided
-- - Human operators must be able to decide not to use the system
--
-- This migration creates the foundation for:
-- - Approval queue for high-risk decisions flagged by policies
-- - Override tracking with full audit trail
-- - Decision chain linking for traceability

-- =============================================================================
-- HITL Approval Queue Table
-- =============================================================================
-- Stores requests that require human approval before AI can proceed.
-- Linked to policies with action='alert' (EU AI Act Article 14 triggers).
CREATE TABLE IF NOT EXISTS hitl_approval_queue (
    id BIGSERIAL PRIMARY KEY,

    -- Unique identifier for this approval request
    request_id UUID NOT NULL DEFAULT gen_random_uuid(),

    -- Multi-tenant isolation (RLS enabled)
    org_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,

    -- Request context
    client_id VARCHAR(100) NOT NULL,
    user_id VARCHAR(255),

    -- The original request that triggered oversight
    original_query TEXT NOT NULL,
    request_type VARCHAR(50) NOT NULL,  -- llm_chat, sql, mcp-query, etc.
    request_context JSONB DEFAULT '{}',

    -- Policy that triggered the oversight requirement
    triggered_policy_id VARCHAR(100) NOT NULL,
    triggered_policy_name VARCHAR(255) NOT NULL,
    trigger_reason TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'high',  -- low, medium, high, critical

    -- EU AI Act metadata
    eu_ai_act_article VARCHAR(10),  -- e.g., '14' for Human Oversight
    compliance_framework VARCHAR(50) DEFAULT 'EU_AI_Act',
    risk_classification VARCHAR(50) DEFAULT 'high-risk_ai_system',

    -- Status tracking
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending, approved, rejected, expired, overridden

    -- Reviewer information (populated when reviewed)
    reviewer_id VARCHAR(255),
    reviewer_email VARCHAR(255),
    reviewer_role VARCHAR(100),
    review_comment TEXT,
    reviewed_at TIMESTAMP WITH TIME ZONE,

    -- Override tracking (if manually overridden)
    override_justification TEXT,
    override_authorized_by VARCHAR(255),

    -- Expiration (requests expire if not reviewed)
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT hitl_valid_status CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'overridden')),
    CONSTRAINT hitl_valid_severity CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    -- Ensure reviewer is set when status requires it
    CONSTRAINT hitl_reviewed_requires_reviewer CHECK (
        status NOT IN ('approved', 'rejected') OR reviewer_id IS NOT NULL
    ),
    -- Ensure override justification is set when status is overridden
    CONSTRAINT hitl_override_requires_justification CHECK (
        status != 'overridden' OR override_justification IS NOT NULL
    )
);

-- Unique constraint on request_id
CREATE UNIQUE INDEX IF NOT EXISTS idx_hitl_request_id ON hitl_approval_queue(request_id);

-- Performance indexes for common queries
CREATE INDEX IF NOT EXISTS idx_hitl_org_status ON hitl_approval_queue(org_id, status);
CREATE INDEX IF NOT EXISTS idx_hitl_tenant_status ON hitl_approval_queue(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_hitl_status_created ON hitl_approval_queue(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_hitl_pending_expires ON hitl_approval_queue(status, expires_at)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_hitl_reviewer ON hitl_approval_queue(reviewer_id, reviewed_at DESC)
    WHERE reviewer_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hitl_policy ON hitl_approval_queue(triggered_policy_id);

-- =============================================================================
-- HITL Approval History Table
-- =============================================================================
-- Immutable audit trail of all approval actions (for EU AI Act Article 12 compliance).
-- Separate from queue to ensure history is never modified.
CREATE TABLE IF NOT EXISTS hitl_approval_history (
    id BIGSERIAL PRIMARY KEY,

    -- Reference to the original request
    request_id UUID NOT NULL,

    -- Multi-tenant isolation
    org_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,

    -- Action taken
    action VARCHAR(20) NOT NULL,  -- created, approved, rejected, expired, overridden

    -- Actor who performed the action
    actor_id VARCHAR(255),
    actor_email VARCHAR(255),
    actor_role VARCHAR(100),
    actor_ip VARCHAR(64),  -- IPv4, IPv6, or IPv6 with zone ID

    -- Action details
    comment TEXT,
    justification TEXT,

    -- State at time of action
    previous_status VARCHAR(20),
    new_status VARCHAR(20),

    -- Immutable timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,

    -- Constraint
    CONSTRAINT hitl_history_valid_action CHECK (action IN ('created', 'approved', 'rejected', 'expired', 'overridden', 'escalated'))
);

-- Indexes for history queries
CREATE INDEX IF NOT EXISTS idx_hitl_history_request ON hitl_approval_history(request_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_hitl_history_org ON hitl_approval_history(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_hitl_history_actor ON hitl_approval_history(actor_id, created_at DESC);

-- =============================================================================
-- Decision Chain Table (for EU AI Act Article 12 Traceability)
-- =============================================================================
-- Links all decisions in a request chain for full traceability.
-- Used for generating EU AI Act conformity evidence.
CREATE TABLE IF NOT EXISTS decision_chain (
    id BIGSERIAL PRIMARY KEY,

    -- Chain identifier (groups related decisions)
    chain_id UUID NOT NULL DEFAULT gen_random_uuid(),

    -- Multi-tenant isolation
    org_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255),  -- Optional for cross-tenant queries

    -- Step in the decision chain (1, 2, 3...)
    step_number INTEGER NOT NULL DEFAULT 1,

    -- Decision type
    decision_type VARCHAR(50) NOT NULL,  -- policy_eval, llm_call, hitl_review, override, etc.

    -- Actor (system or human)
    actor_type VARCHAR(20) NOT NULL,  -- system, human, ai
    actor_id VARCHAR(255),

    -- Decision details
    input_summary TEXT,
    output_summary TEXT,
    decision_made VARCHAR(100),  -- approved, blocked, redacted, etc.
    reasoning TEXT,

    -- Confidence/certainty (for AI decisions)
    confidence_score DECIMAL(5,4) CHECK (confidence_score IS NULL OR (confidence_score >= 0 AND confidence_score <= 1)),  -- 0.0000 to 1.0000

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Performance
    processing_time_ms INTEGER,

    -- Timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,

    -- Constraint
    CONSTRAINT decision_valid_actor_type CHECK (actor_type IN ('system', 'human', 'ai'))
);

-- Indexes for decision chain queries
CREATE INDEX IF NOT EXISTS idx_decision_chain_id ON decision_chain(chain_id, step_number);
CREATE INDEX IF NOT EXISTS idx_decision_chain_org ON decision_chain(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_decision_chain_type ON decision_chain(decision_type, created_at DESC);

-- =============================================================================
-- Row-Level Security Policies
-- =============================================================================
-- Enable RLS for multi-tenant isolation
ALTER TABLE hitl_approval_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE hitl_approval_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_chain ENABLE ROW LEVEL SECURITY;

-- HITL Queue: Users can only see/modify their org's requests
-- Uses get_current_org_id() helper from migration 018 for consistency
CREATE POLICY hitl_queue_tenant_isolation ON hitl_approval_queue
    FOR ALL
    USING (org_id = get_current_org_id())
    WITH CHECK (org_id = get_current_org_id());

-- HITL History: Users can only see their org's history (no modifications allowed via policy)
CREATE POLICY hitl_history_tenant_isolation ON hitl_approval_history
    FOR SELECT
    USING (org_id = get_current_org_id());

-- HITL History: Insert allowed for same org
CREATE POLICY hitl_history_insert ON hitl_approval_history
    FOR INSERT
    WITH CHECK (org_id = get_current_org_id());

-- Decision Chain: Users can only see their org's chains
CREATE POLICY decision_chain_tenant_isolation ON decision_chain
    FOR ALL
    USING (org_id = get_current_org_id())
    WITH CHECK (org_id = get_current_org_id());

-- =============================================================================
-- Helper Functions
-- =============================================================================

-- Function to expire old pending requests (atomic update + history insert)
-- Uses CTE to avoid race condition between UPDATE and INSERT
CREATE OR REPLACE FUNCTION expire_hitl_requests()
RETURNS INTEGER AS $$
DECLARE
    expired_count INTEGER;
BEGIN
    -- Atomically update expired requests and capture them for history logging
    WITH expired AS (
        UPDATE hitl_approval_queue
        SET
            status = 'expired',
            updated_at = CURRENT_TIMESTAMP
        WHERE
            status = 'pending'
            AND expires_at < CURRENT_TIMESTAMP
        RETURNING request_id, org_id, tenant_id
    )
    -- Immediately insert into history within the same transaction
    INSERT INTO hitl_approval_history (
        request_id, org_id, tenant_id, action,
        previous_status, new_status, created_at
    )
    SELECT
        request_id, org_id, tenant_id, 'expired',
        'pending', 'expired', CURRENT_TIMESTAMP
    FROM expired;

    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get pending approval count for dashboard
CREATE OR REPLACE FUNCTION get_hitl_pending_count(p_org_id VARCHAR)
RETURNS TABLE (
    total_pending BIGINT,
    high_priority BIGINT,
    critical_priority BIGINT,
    oldest_pending_hours NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        COUNT(*) FILTER (WHERE status = 'pending') as total_pending,
        COUNT(*) FILTER (WHERE status = 'pending' AND severity = 'high') as high_priority,
        COUNT(*) FILTER (WHERE status = 'pending' AND severity = 'critical') as critical_priority,
        EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - MIN(created_at) FILTER (WHERE status = 'pending'))) / 3600 as oldest_pending_hours
    FROM hitl_approval_queue
    WHERE org_id = p_org_id;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Views for Reporting
-- =============================================================================

-- Pending approvals summary view
CREATE OR REPLACE VIEW hitl_pending_summary AS
SELECT
    org_id,
    tenant_id,
    triggered_policy_name,
    severity,
    COUNT(*) as pending_count,
    MIN(created_at) as oldest_request,
    MAX(expires_at) as next_expiry
FROM hitl_approval_queue
WHERE status = 'pending'
GROUP BY org_id, tenant_id, triggered_policy_name, severity
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        ELSE 4
    END,
    oldest_request ASC;

-- EU AI Act compliance metrics view
CREATE OR REPLACE VIEW eu_ai_act_hitl_metrics AS
SELECT
    org_id,
    DATE_TRUNC('day', created_at) as day,
    eu_ai_act_article,
    COUNT(*) as total_requests,
    COUNT(*) FILTER (WHERE status = 'approved') as approved_count,
    COUNT(*) FILTER (WHERE status = 'rejected') as rejected_count,
    COUNT(*) FILTER (WHERE status = 'overridden') as override_count,
    COUNT(*) FILTER (WHERE status = 'expired') as expired_count,
    AVG(EXTRACT(EPOCH FROM (reviewed_at - created_at))) FILTER (WHERE reviewed_at IS NOT NULL) as avg_review_time_seconds
FROM hitl_approval_queue
WHERE eu_ai_act_article IS NOT NULL
GROUP BY org_id, DATE_TRUNC('day', created_at), eu_ai_act_article
ORDER BY day DESC, eu_ai_act_article;

-- =============================================================================
-- Triggers for updated_at columns
-- =============================================================================
-- Uses update_updated_at_column() function from migration 010_policy_tables.sql

-- Trigger for hitl_approval_queue
DROP TRIGGER IF EXISTS update_hitl_queue_updated_at ON hitl_approval_queue;
CREATE TRIGGER update_hitl_queue_updated_at
    BEFORE UPDATE ON hitl_approval_queue
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Success Message
-- =============================================================================
DO $$
BEGIN
    RAISE NOTICE '✅ EU AI Act HITL Oversight Queue Migration Complete';
    RAISE NOTICE '';
    RAISE NOTICE 'Tables Created:';
    RAISE NOTICE '  1. hitl_approval_queue - Pending approval requests';
    RAISE NOTICE '  2. hitl_approval_history - Immutable audit trail';
    RAISE NOTICE '  3. decision_chain - Full decision traceability';
    RAISE NOTICE '';
    RAISE NOTICE 'Functions Created:';
    RAISE NOTICE '  - expire_hitl_requests() - Expire stale pending requests';
    RAISE NOTICE '  - get_hitl_pending_count(org_id) - Dashboard metrics';
    RAISE NOTICE '';
    RAISE NOTICE 'Views Created:';
    RAISE NOTICE '  - hitl_pending_summary - Pending approval summary';
    RAISE NOTICE '  - eu_ai_act_hitl_metrics - EU AI Act compliance metrics';
    RAISE NOTICE '';
    RAISE NOTICE 'EU AI Act Compliance:';
    RAISE NOTICE '  - Article 12: Full audit trail in hitl_approval_history';
    RAISE NOTICE '  - Article 14: Human oversight queue and override tracking';
END $$;
