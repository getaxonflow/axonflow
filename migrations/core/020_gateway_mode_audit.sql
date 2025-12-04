-- Migration 020: Gateway Mode Audit Tables
-- Created: 2025-11-28
-- Purpose: Store gateway mode pre-check contexts and LLM call audits
--
-- These tables support the Gateway Mode SDK where:
-- 1. Client calls getPolicyApprovedContext() before making LLM call
-- 2. Client makes LLM call directly to provider
-- 3. Client calls auditLLMCall() to report back for audit

-- Gateway Contexts Table
-- Stores pre-check contexts that link to audit records
-- Contexts expire after 5 minutes (configurable)
CREATE TABLE IF NOT EXISTS gateway_contexts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    context_id VARCHAR(64) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    user_token_hash VARCHAR(64),      -- SHA256 hash of user token (privacy)
    query_hash VARCHAR(64),           -- SHA256 hash of query (privacy)
    data_sources TEXT[],              -- MCP connectors accessed
    policies_evaluated TEXT[],        -- Policies that were evaluated
    approved BOOLEAN NOT NULL,        -- Whether request was approved
    block_reason TEXT,                -- Reason if blocked
    expires_at TIMESTAMP NOT NULL,    -- Context validity window
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for gateway_contexts
CREATE INDEX IF NOT EXISTS idx_gateway_contexts_context_id ON gateway_contexts(context_id);
CREATE INDEX IF NOT EXISTS idx_gateway_contexts_client_id ON gateway_contexts(client_id);
CREATE INDEX IF NOT EXISTS idx_gateway_contexts_created_at ON gateway_contexts(created_at);
CREATE INDEX IF NOT EXISTS idx_gateway_contexts_expires_at ON gateway_contexts(expires_at);

-- LLM Call Audits Table
-- Stores audit records for LLM calls made by clients in Gateway Mode
-- Linked to gateway_contexts via context_id
CREATE TABLE IF NOT EXISTS llm_call_audits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id VARCHAR(64) UNIQUE NOT NULL,
    context_id VARCHAR(64) REFERENCES gateway_contexts(context_id),
    client_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,    -- openai, anthropic, bedrock, ollama
    model VARCHAR(100) NOT NULL,      -- gpt-4, claude-3-sonnet, etc.
    prompt_tokens INT,
    completion_tokens INT,
    total_tokens INT,
    latency_ms BIGINT,
    estimated_cost_usd DECIMAL(10, 6),
    response_summary_hash VARCHAR(64), -- Hash of response for linkage
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for llm_call_audits
CREATE INDEX IF NOT EXISTS idx_llm_call_audits_audit_id ON llm_call_audits(audit_id);
CREATE INDEX IF NOT EXISTS idx_llm_call_audits_context_id ON llm_call_audits(context_id);
CREATE INDEX IF NOT EXISTS idx_llm_call_audits_client_id ON llm_call_audits(client_id);
CREATE INDEX IF NOT EXISTS idx_llm_call_audits_provider ON llm_call_audits(provider);
CREATE INDEX IF NOT EXISTS idx_llm_call_audits_model ON llm_call_audits(model);
CREATE INDEX IF NOT EXISTS idx_llm_call_audits_created_at ON llm_call_audits(created_at);

-- Cost aggregation index (for Phase 3: Cost Intelligence)
CREATE INDEX IF NOT EXISTS idx_llm_call_audits_cost_aggregation
    ON llm_call_audits(client_id, provider, model, created_at);

-- Add comment documenting the tables
COMMENT ON TABLE gateway_contexts IS 'Gateway Mode pre-check contexts - links policy approval to audit trail';
COMMENT ON TABLE llm_call_audits IS 'Gateway Mode LLM call audits - tracks all LLM calls with cost estimation';

-- Cleanup function for expired contexts (can be called via cron or Agent)
CREATE OR REPLACE FUNCTION cleanup_expired_gateway_contexts()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM gateway_contexts
    WHERE expires_at < NOW() - INTERVAL '1 day'
    AND context_id NOT IN (
        SELECT DISTINCT context_id FROM llm_call_audits WHERE context_id IS NOT NULL
    );
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_gateway_contexts IS 'Removes expired gateway contexts that have no linked audits (retention: 1 day after expiry)';

-- Summary view for cost analysis (used by Phase 3: Cost Intelligence)
CREATE OR REPLACE VIEW llm_cost_summary AS
SELECT
    client_id,
    provider,
    model,
    DATE_TRUNC('day', created_at) AS date,
    COUNT(*) AS call_count,
    SUM(prompt_tokens) AS total_prompt_tokens,
    SUM(completion_tokens) AS total_completion_tokens,
    SUM(total_tokens) AS total_tokens,
    SUM(estimated_cost_usd) AS total_cost_usd,
    AVG(latency_ms) AS avg_latency_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95_latency_ms
FROM llm_call_audits
GROUP BY client_id, provider, model, DATE_TRUNC('day', created_at);

COMMENT ON VIEW llm_cost_summary IS 'Daily summary of LLM costs by client, provider, and model';
