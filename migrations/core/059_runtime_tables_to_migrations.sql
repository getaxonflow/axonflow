-- Migration 059: Move runtime-created tables to proper migrations
-- Date: 2026-04-04
-- Context: Issue #1498 — 2 tables were created at runtime by orchestrator
-- startup code (CREATE TABLE IF NOT EXISTS) instead of via migrations.
-- This caused failures when subsequent migrations tried to ALTER these
-- tables on fresh installs (e.g., #1492 migration 061 failed because
-- audit_logs didn't exist yet).
--
-- Note: dynamic_policies and policy_metrics are NOT included here because
-- they already exist in migration 010_policy_tables.sql. The runtime
-- CREATE TABLE for those was always a no-op (stale schema that never
-- took effect because 010 runs first).
--
-- IF NOT EXISTS ensures idempotency for existing deployments where the
-- orchestrator already created these tables at runtime.

-- =============================================================================
-- Table 1: audit_logs (was: platform/orchestrator/audit_logger.go)
-- =============================================================================
-- This is the primary audit log table for all request/response auditing.
-- Not to be confused with agent_audit_logs or orchestrator_audit_logs
-- (migration 011) which are component-specific diagnostic logs.
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(255) PRIMARY KEY,
    request_id VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    user_id INTEGER NOT NULL,
    user_email VARCHAR(255) NOT NULL,
    user_role VARCHAR(50) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    org_id VARCHAR(255),
    request_type VARCHAR(50) NOT NULL,
    query TEXT NOT NULL,
    query_hash VARCHAR(255) NOT NULL,
    policy_decision VARCHAR(50) NOT NULL,
    policy_details JSONB,
    provider VARCHAR(50),
    model VARCHAR(100),
    response_time_ms BIGINT,
    tokens_used INTEGER,
    cost DECIMAL(10, 6),
    redacted_fields JSONB,
    error_message TEXT,
    response_sample TEXT,
    compliance_flags JSONB,
    security_metrics JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- For existing deployments where audit_logs was created at runtime without
-- org_id, add the column. Fresh installs get it from CREATE TABLE above.
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_email ON audit_logs(user_email);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_policy_decision ON audit_logs(policy_decision);
CREATE INDEX IF NOT EXISTS idx_audit_logs_org_id ON audit_logs(org_id);

-- =============================================================================
-- Table 2: media_governance_config (was: platform/orchestrator/media_governance_config.go)
-- =============================================================================
-- Per-tenant media governance configuration (Enterprise feature).
CREATE TABLE IF NOT EXISTS media_governance_config (
    tenant_id VARCHAR(100) PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT true,
    allowed_analyzers JSONB DEFAULT '[]',
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(255)
);
