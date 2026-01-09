-- Migration 039: MCP Policy Phases for Tiered Enforcement
-- Date: 2026-01-08
-- Purpose: Add phase-aware policy evaluation for MCP requests
-- Related: ADR-022, Issue #963 (EPIC), Issue #975 (Engine)
--
-- This migration enables:
-- 1. Request-phase policy evaluation (block queries containing PII/SQLi)
-- 2. Response-phase policy evaluation (redact PII in results)
-- 3. Per-phase action configuration (different actions for request vs response)
-- 4. Policy evaluation metrics for observability

-- =============================================================================
-- PHASE 1: Add phase column to static_policies
-- =============================================================================

-- Add phase column: specifies when the policy is evaluated
-- 'request'  - Only evaluated before connector execution (fast blocking)
-- 'response' - Only evaluated after connector execution (redaction)
-- 'both'     - Evaluated in both phases (default, backward compatible)
ALTER TABLE static_policies
ADD COLUMN IF NOT EXISTS phase VARCHAR(20) DEFAULT 'both';

-- Add constraint for valid phase values
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'static_policies_phase_check'
    ) THEN
        ALTER TABLE static_policies
        ADD CONSTRAINT static_policies_phase_check
        CHECK (phase IN ('request', 'response', 'both'));
    END IF;
END $$;

-- =============================================================================
-- PHASE 2: Add phase-specific action columns
-- =============================================================================

-- action_request: What to do when policy matches in request phase
-- Valid values: 'block', 'allow', 'log', 'warn'
-- NULL means use the default 'action' column behavior
ALTER TABLE static_policies
ADD COLUMN IF NOT EXISTS action_request VARCHAR(50);

-- action_response: What to do when policy matches in response phase
-- Valid values: 'block', 'redact', 'allow', 'log', 'warn'
-- NULL means use the default 'action' column behavior
ALTER TABLE static_policies
ADD COLUMN IF NOT EXISTS action_response VARCHAR(50);

-- Add constraints for valid action values
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'static_policies_action_request_check'
    ) THEN
        ALTER TABLE static_policies
        ADD CONSTRAINT static_policies_action_request_check
        CHECK (action_request IS NULL OR action_request IN ('block', 'allow', 'log', 'warn'));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'static_policies_action_response_check'
    ) THEN
        ALTER TABLE static_policies
        ADD CONSTRAINT static_policies_action_response_check
        CHECK (action_response IS NULL OR action_response IN ('block', 'redact', 'allow', 'log', 'warn'));
    END IF;
END $$;

-- =============================================================================
-- PHASE 3: Update existing policies with appropriate phase values
-- =============================================================================

-- SQL Injection policies: block on both request and response
-- These are security-critical and should never allow SQLi patterns through
UPDATE static_policies
SET phase = 'both',
    action_request = 'block',
    action_response = 'block'
WHERE category LIKE 'security-sqli%'
  AND action_request IS NULL
  AND phase = 'both';

-- Dangerous query policies: block on request only
-- These prevent destructive operations like DROP TABLE
UPDATE static_policies
SET phase = 'request',
    action_request = 'block',
    action_response = NULL
WHERE category LIKE 'security-dangerous%'
  AND action_request IS NULL;

-- Critical PII policies: warn on request (flag for redaction), redact on response
-- Issue #891: PII detection is non-blocking - preserves UX while ensuring redaction
-- The request phase flags for redaction, the response phase performs actual redaction
UPDATE static_policies
SET phase = 'both',
    action_request = 'warn',
    action_response = 'redact'
WHERE category LIKE 'pii-%'
  AND severity = 'critical'
  AND action_request IS NULL;

-- Non-critical PII policies: log on request (allow querying), redact on response
-- Less sensitive data like email may be needed for lookups but should be redacted
UPDATE static_policies
SET phase = 'both',
    action_request = 'log',
    action_response = 'redact'
WHERE category LIKE 'pii-%'
  AND severity IN ('medium', 'high')
  AND action_request IS NULL;

-- Low severity PII (like booking references): log only for audit trail
UPDATE static_policies
SET phase = 'both',
    action_request = 'log',
    action_response = 'log'
WHERE category LIKE 'pii-%'
  AND severity = 'low'
  AND action_request IS NULL;

-- Admin access policies: block on request only
UPDATE static_policies
SET phase = 'request',
    action_request = 'block',
    action_response = NULL
WHERE category LIKE 'admin-access%'
  AND action_request IS NULL;

-- Data exfiltration policies: response only (detect large data transfers)
UPDATE static_policies
SET phase = 'response',
    action_request = NULL,
    action_response = 'block'
WHERE category LIKE 'data-exfiltration%'
  AND action_response IS NULL;

-- =============================================================================
-- PHASE 4: Add indexes for efficient phase-aware queries
-- =============================================================================

-- Index for request-phase policy lookup
-- Used when evaluating policies before connector execution
CREATE INDEX IF NOT EXISTS idx_static_policies_request_phase
ON static_policies(tenant_id, category, priority DESC)
WHERE enabled = true
  AND phase IN ('request', 'both')
  AND deleted_at IS NULL;

-- Index for response-phase policy lookup
-- Used when evaluating policies after connector execution
CREATE INDEX IF NOT EXISTS idx_static_policies_response_phase
ON static_policies(tenant_id, category, priority DESC)
WHERE enabled = true
  AND phase IN ('response', 'both')
  AND deleted_at IS NULL;

-- Composite index for MCP policy evaluation
-- Optimized for the common case of evaluating all applicable policies
CREATE INDEX IF NOT EXISTS idx_static_policies_mcp_eval
ON static_policies(tenant_id, phase, category, priority DESC)
WHERE enabled = true
  AND deleted_at IS NULL;

-- =============================================================================
-- PHASE 5: Create policy_evaluations table for metrics
-- =============================================================================

-- This table stores policy evaluation metrics for observability
-- Allows tracking of policy performance, hit rates, and blocking behavior
CREATE TABLE IF NOT EXISTS policy_evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Evaluation context
    evaluation_type VARCHAR(20) NOT NULL
        CHECK (evaluation_type IN ('request', 'response')),
    tenant_id VARCHAR(100) NOT NULL,
    organization_id UUID,
    connector_name VARCHAR(100),
    user_id VARCHAR(100),

    -- Input summary (not the full content for privacy)
    input_hash VARCHAR(64),  -- SHA-256 of input for deduplication
    input_length INTEGER,

    -- Results
    policies_evaluated INTEGER NOT NULL DEFAULT 0,
    matched_policies JSONB DEFAULT '[]',  -- Array of {policy_id, category, action}
    blocked BOOLEAN NOT NULL DEFAULT false,
    block_reason TEXT,
    redactions_applied INTEGER NOT NULL DEFAULT 0,
    redacted_fields JSONB DEFAULT '[]',  -- Array of field paths that were redacted

    -- Performance
    processing_time_ms INTEGER NOT NULL,
    cache_hit BOOLEAN DEFAULT false,

    -- Timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for querying evaluations by tenant and time
CREATE INDEX IF NOT EXISTS idx_policy_evaluations_tenant_time
ON policy_evaluations(tenant_id, created_at DESC);

-- Index for querying blocked evaluations
CREATE INDEX IF NOT EXISTS idx_policy_evaluations_blocked
ON policy_evaluations(tenant_id, blocked, created_at DESC)
WHERE blocked = true;

-- Index for performance analysis
CREATE INDEX IF NOT EXISTS idx_policy_evaluations_performance
ON policy_evaluations(evaluation_type, processing_time_ms, created_at DESC);

-- Index for time-based queries on recent evaluations
-- Note: Partial indexes with NOW() are not supported (requires IMMUTABLE).
-- Use regular index with explicit time-based WHERE clauses in queries.
CREATE INDEX IF NOT EXISTS idx_policy_evaluations_recent_lookup
ON policy_evaluations(tenant_id, evaluation_type, created_at DESC);

-- =============================================================================
-- PHASE 6: Add RLS policy for multi-tenant isolation
-- =============================================================================

-- Enable RLS on policy_evaluations
ALTER TABLE policy_evaluations ENABLE ROW LEVEL SECURITY;

-- Create policy for tenant isolation
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'policy_evaluations'
        AND policyname = 'policy_evaluations_tenant_isolation'
    ) THEN
        CREATE POLICY policy_evaluations_tenant_isolation
        ON policy_evaluations
        FOR ALL
        USING (
            tenant_id = current_setting('app.tenant_id', true)
            OR current_setting('app.is_admin', true) = 'true'
        );
    END IF;
END $$;

-- =============================================================================
-- PHASE 7: Documentation
-- =============================================================================

COMMENT ON COLUMN static_policies.phase IS
    'When policy is evaluated: request (before connector call), response (after), or both';

COMMENT ON COLUMN static_policies.action_request IS
    'Action for request phase: block (deny query), allow, log (audit only), warn (log + continue)';

COMMENT ON COLUMN static_policies.action_response IS
    'Action for response phase: block (deny response), redact (mask PII), allow, log, warn';

COMMENT ON TABLE policy_evaluations IS
    'Metrics for policy evaluation performance and outcomes. Used for observability and compliance auditing.';

COMMENT ON COLUMN policy_evaluations.matched_policies IS
    'JSON array of policies that matched: [{policy_id, category, severity, action}]';

COMMENT ON COLUMN policy_evaluations.redacted_fields IS
    'JSON array of field paths that were redacted: ["rows[0].ssn", "rows[1].credit_card"]';

-- =============================================================================
-- Migration complete
-- =============================================================================
--
-- Summary of changes:
-- 1. Added 'phase' column to static_policies (request, response, both)
-- 2. Added 'action_request' column for request-phase actions
-- 3. Added 'action_response' column for response-phase actions
-- 4. Updated existing policies with appropriate phase configurations
-- 5. Added indexes for efficient phase-aware policy queries
-- 6. Created policy_evaluations table for metrics
-- 7. Added RLS policy for multi-tenant isolation
--
-- Next steps:
-- - Deploy unified policy engine (platform/shared/policy/)
-- - Integrate into mcp_handler.go
-- - Migrate gateway_handlers.go to use shared engine
