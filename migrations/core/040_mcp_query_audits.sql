-- Migration 040: MCP Query Audits Table
-- Created: 2026-01-15
-- Purpose: Store audit logs for MCP connector queries with policy evaluation results
-- Related: Issue #1006 - MCP Connector Audit Logging
--
-- This table captures all MCP connector operations including:
-- 1. REQUEST phase: SQLi detection, PII blocking
-- 2. RESPONSE phase: PII redaction
-- 3. EXFILTRATION checks: Row/volume limits

-- MCP Query Audits Table
-- Stores audit records for all MCP connector queries
CREATE TABLE IF NOT EXISTS mcp_query_audits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id VARCHAR(64) UNIQUE NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255),
    connector_name VARCHAR(100) NOT NULL,
    operation VARCHAR(50) NOT NULL,          -- query, execute, list_resources, etc.
    statement_hash VARCHAR(64),              -- SHA256 hash of statement (privacy)

    -- Request phase (pre-execution policy evaluation)
    request_blocked BOOLEAN DEFAULT false,
    request_block_reason TEXT,
    request_policies_evaluated INT DEFAULT 0,
    request_matched_policies TEXT[],

    -- Response phase (post-execution policy evaluation)
    response_redacted BOOLEAN DEFAULT false,
    response_redactions_count INT DEFAULT 0,
    response_redacted_fields TEXT[],

    -- Exfiltration detection
    exfil_rows_returned INT,
    exfil_exceeded BOOLEAN DEFAULT false,
    exfil_limit_type VARCHAR(20),            -- row_count, data_volume, etc.

    -- Result
    row_count INT,
    duration_ms BIGINT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_mcp_query_audits_tenant_time
    ON mcp_query_audits(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mcp_query_audits_client_time
    ON mcp_query_audits(client_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mcp_query_audits_connector
    ON mcp_query_audits(connector_name, created_at DESC);

-- Partial index for blocked requests (common compliance query)
CREATE INDEX IF NOT EXISTS idx_mcp_query_audits_blocked
    ON mcp_query_audits(request_blocked, created_at DESC)
    WHERE request_blocked = true;

-- Partial index for redacted responses
CREATE INDEX IF NOT EXISTS idx_mcp_query_audits_redacted
    ON mcp_query_audits(response_redacted, created_at DESC)
    WHERE response_redacted = true;

-- Partial index for exfiltration violations
CREATE INDEX IF NOT EXISTS idx_mcp_query_audits_exfil
    ON mcp_query_audits(exfil_exceeded, created_at DESC)
    WHERE exfil_exceeded = true;

-- Table documentation
COMMENT ON TABLE mcp_query_audits IS 'Audit log for MCP connector queries with policy evaluation results';
COMMENT ON COLUMN mcp_query_audits.audit_id IS 'Unique identifier for the audit entry, can be used to correlate with SDK PolicyInfo';
COMMENT ON COLUMN mcp_query_audits.statement_hash IS 'SHA256 hash of the SQL/query statement for linkage without storing raw queries';
COMMENT ON COLUMN mcp_query_audits.request_matched_policies IS 'Policies that triggered during request phase evaluation';
COMMENT ON COLUMN mcp_query_audits.response_redacted_fields IS 'Field paths that were redacted (e.g., ["$.users[*].ssn", "$.users[*].email"])';
COMMENT ON COLUMN mcp_query_audits.exfil_limit_type IS 'Type of exfiltration limit exceeded: row_count, data_volume, time_window';

-- Summary view for MCP audit analysis
CREATE OR REPLACE VIEW mcp_query_audit_summary AS
SELECT
    tenant_id,
    connector_name,
    DATE_TRUNC('day', created_at) AS date,
    COUNT(*) AS total_queries,
    COUNT(*) FILTER (WHERE request_blocked = true) AS blocked_queries,
    COUNT(*) FILTER (WHERE response_redacted = true) AS redacted_queries,
    COUNT(*) FILTER (WHERE exfil_exceeded = true) AS exfil_violations,
    COUNT(*) FILTER (WHERE success = true) AS successful_queries,
    AVG(duration_ms) AS avg_duration_ms,
    SUM(row_count) AS total_rows_returned
FROM mcp_query_audits
GROUP BY tenant_id, connector_name, DATE_TRUNC('day', created_at);

COMMENT ON VIEW mcp_query_audit_summary IS 'Daily summary of MCP query audits by tenant and connector';
