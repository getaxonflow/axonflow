-- Migration 010: Policy Tables
-- Date: 2025-11-20
-- Purpose: Move policy tables from manual schema files to proper migrations
-- Source: platform/database/policy_schema.sql (most complete version)
-- Related: Issue #19 - AWS Marketplace schema consistency

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- Static Policies Table (for Agent)
-- =============================================================================
-- These are fast, rule-based policies evaluated by the Agent
CREATE TABLE IF NOT EXISTS static_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id VARCHAR(255), -- Multi-tenant isolation column for RLS
    policy_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(50) NOT NULL, -- 'sql_injection', 'dangerous_queries', 'admin_access', 'pii_detection'
    pattern VARCHAR(500) NOT NULL, -- Regex pattern or rule
    severity VARCHAR(20) NOT NULL DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    description TEXT,
    action VARCHAR(50) NOT NULL DEFAULT 'block', -- 'block', 'allow', 'redact', 'log'
    enabled BOOLEAN DEFAULT true,
    tenant_id VARCHAR(100) DEFAULT 'global', -- For multi-tenant support
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    version INTEGER DEFAULT 1
);

-- Static policies indexes
CREATE INDEX IF NOT EXISTS idx_static_policies_category ON static_policies(category) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_static_policies_tenant ON static_policies(tenant_id) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_static_policies_severity ON static_policies(severity) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_static_policies_enabled ON static_policies(enabled);

-- =============================================================================
-- Dynamic Policies Table (for Orchestrator)
-- =============================================================================
-- These are context-aware policies with more complex evaluation logic
-- IMPORTANT: Schema matches orchestrator expectations (v1.0.9 fixes)
-- Uses policy_type (not type), conditions JSONB, actions JSONB
CREATE TABLE IF NOT EXISTS dynamic_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id VARCHAR(255), -- Multi-tenant isolation column for RLS
    policy_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    policy_type VARCHAR(50) NOT NULL, -- 'risk_based', 'context_aware', 'workflow', 'compliance'
    risk_threshold DECIMAL(3,2), -- 0.00 to 1.00 risk score threshold
    conditions JSONB NOT NULL, -- Complex conditions for policy evaluation (array)
    actions JSONB NOT NULL, -- Actions to take when policy triggers (array)
    priority INTEGER DEFAULT 100, -- Higher priority policies evaluated first
    enabled BOOLEAN DEFAULT true,
    tenant_id VARCHAR(100) DEFAULT 'global',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    version INTEGER DEFAULT 1
);

-- Fix legacy schema: rename 'type' to 'policy_type' if needed (handles production database)
DO $$
BEGIN
    -- Check if legacy column 'type' exists instead of 'policy_type'
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'dynamic_policies' AND column_name = 'type'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'dynamic_policies' AND column_name = 'policy_type'
    ) THEN
        -- Rename 'type' to 'policy_type' for consistency
        ALTER TABLE dynamic_policies RENAME COLUMN type TO policy_type;
        RAISE NOTICE 'Renamed dynamic_policies.type to policy_type for schema consistency';
    END IF;

    -- Add description column if missing (legacy tables may not have it)
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'dynamic_policies' AND column_name = 'description'
    ) THEN
        ALTER TABLE dynamic_policies ADD COLUMN description TEXT;
        RAISE NOTICE 'Added description column to dynamic_policies';
    END IF;
END $$;

-- Dynamic policies indexes (now safe to create with policy_type)
CREATE INDEX IF NOT EXISTS idx_dynamic_policies_type ON dynamic_policies(policy_type) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_dynamic_policies_tenant ON dynamic_policies(tenant_id) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_dynamic_policies_priority ON dynamic_policies(priority DESC) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_dynamic_policies_enabled_priority ON dynamic_policies(enabled, priority DESC);

-- =============================================================================
-- Policy Evaluation Cache Table
-- =============================================================================
-- Caches recent policy evaluations for performance
CREATE TABLE IF NOT EXISTS policy_evaluation_cache (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id VARCHAR(255), -- Multi-tenant isolation column for RLS
    cache_key VARCHAR(255) UNIQUE NOT NULL,
    policy_type VARCHAR(20) NOT NULL, -- 'static' or 'dynamic'
    evaluation_result JSONB NOT NULL,
    ttl_seconds INTEGER DEFAULT 300,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() + INTERVAL '5 minutes'
);

-- Policy cache indexes
CREATE INDEX IF NOT EXISTS idx_policy_cache_key ON policy_evaluation_cache(cache_key);
CREATE INDEX IF NOT EXISTS idx_policy_cache_expires ON policy_evaluation_cache(expires_at);

-- =============================================================================
-- Policy Metrics Table
-- =============================================================================
-- Tracks policy performance and hit rates
-- IMPORTANT: Schema supports both per-request metrics (policy_name) and aggregated metrics (policy_id)
CREATE TABLE IF NOT EXISTS policy_metrics (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(255), -- Multi-tenant isolation column for RLS
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    policy_name VARCHAR(255), -- Used by orchestrator for per-request metrics
    policy_id VARCHAR(100),  -- Optional: for aggregated metrics
    policy_type VARCHAR(20), -- 'static' or 'dynamic'
    execution_time_ms INTEGER,
    success BOOLEAN,
    tenant_id VARCHAR(100),
    hit_count BIGINT DEFAULT 0,
    block_count BIGINT DEFAULT 0,
    allow_count BIGINT DEFAULT 0,
    avg_evaluation_ms DECIMAL(10,2),
    last_triggered TIMESTAMP WITH TIME ZONE,
    date DATE DEFAULT CURRENT_DATE
);

-- Policy metrics indexes
CREATE INDEX IF NOT EXISTS idx_policy_metrics_policy ON policy_metrics(policy_id, date);
CREATE INDEX IF NOT EXISTS idx_policy_metrics_name ON policy_metrics(policy_name);
CREATE INDEX IF NOT EXISTS idx_policy_metrics_tenant ON policy_metrics(tenant_id);
CREATE INDEX IF NOT EXISTS idx_policy_metrics_timestamp ON policy_metrics(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_policy_metrics_date ON policy_metrics(date);

-- =============================================================================
-- Policy Violations Table
-- =============================================================================
-- Audit trail for policy violations
CREATE TABLE IF NOT EXISTS policy_violations (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(255), -- Multi-tenant isolation column for RLS
    violation_type VARCHAR(100),
    severity VARCHAR(20),
    client_id VARCHAR(100),
    user_id VARCHAR(100),
    description TEXT,
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Fix legacy schema: rename 'timestamp' to 'created_at' if needed (handles production database)
DO $$
BEGIN
    -- Check if legacy column 'timestamp' exists instead of 'created_at'
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'policy_violations' AND column_name = 'timestamp'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'policy_violations' AND column_name = 'created_at'
    ) THEN
        -- Rename 'timestamp' to 'created_at' for consistency
        ALTER TABLE policy_violations RENAME COLUMN timestamp TO created_at;
        RAISE NOTICE 'Renamed policy_violations.timestamp to created_at for schema consistency';
    END IF;
END $$;

-- Policy violations indexes (now safe to create with created_at)
CREATE INDEX IF NOT EXISTS idx_policy_violations_client ON policy_violations(client_id);
CREATE INDEX IF NOT EXISTS idx_policy_violations_created ON policy_violations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_policy_violations_severity ON policy_violations(severity);

-- =============================================================================
-- Triggers and Functions
-- =============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for static_policies
-- Drop first to make idempotent (triggers don't support IF NOT EXISTS)
DROP TRIGGER IF EXISTS update_static_policies_updated_at ON static_policies;
CREATE TRIGGER update_static_policies_updated_at
    BEFORE UPDATE ON static_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger for dynamic_policies
DROP TRIGGER IF EXISTS update_dynamic_policies_updated_at ON dynamic_policies;
CREATE TRIGGER update_dynamic_policies_updated_at
    BEFORE UPDATE ON dynamic_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to clean expired cache entries
CREATE OR REPLACE FUNCTION clean_expired_cache()
RETURNS void AS $$
BEGIN
    DELETE FROM policy_evaluation_cache WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Helper Functions
-- =============================================================================

-- Function to get dynamic policies by tenant
CREATE OR REPLACE FUNCTION get_dynamic_policies_for_tenant(p_tenant_id VARCHAR)
RETURNS TABLE (
    policy_id VARCHAR,
    name VARCHAR,
    policy_type VARCHAR,
    conditions JSONB,
    actions JSONB,
    priority INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        dp.policy_id,
        dp.name,
        dp.policy_type,
        dp.conditions,
        dp.actions,
        dp.priority
    FROM dynamic_policies dp
    WHERE dp.enabled = true
      AND (dp.tenant_id IS NULL OR dp.tenant_id = 'global' OR dp.tenant_id = p_tenant_id)
    ORDER BY dp.priority DESC;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Default Policies (Seed Data)
-- =============================================================================
-- Note: Comprehensive seed data from policy_schema.sql not included here
-- Seed data will be loaded via platform/agent/migrations/001_eu_ai_act_travel_templates.sql
-- and other application-level seeding mechanisms

-- Insert only essential default policies for basic functionality
INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, tenant_id) VALUES
('sql_injection_union', 'SQL Injection - UNION Attack', 'sql_injection', 'union\s+select', 'critical', 'UNION-based SQL injection attempt', 'block', 'global'),
('sql_injection_or', 'SQL Injection - OR Condition', 'sql_injection', '(\bor\b|\band\b).*[''"]?\s*[=<>].*[''"]?\s*(or|and)\s*[''"]?\s*[=<>]', 'critical', 'Boolean-based SQL injection attempt', 'block', 'global'),
('drop_table_prevention', 'DROP TABLE Prevention', 'dangerous_queries', 'drop\s+table', 'critical', 'DROP TABLE operations are not allowed', 'block', 'global'),
('truncate_prevention', 'TRUNCATE Prevention', 'dangerous_queries', 'truncate\s+table', 'critical', 'TRUNCATE operations are not allowed', 'block', 'global'),
-- PII Detection policy (credit card detection is in 014_eu_ai_act_templates.sql as eu_gdpr_credit_card_detection)
('pii_ssn_detection', 'SSN Detection', 'pii_detection', '\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b', 'high', 'US Social Security Number pattern detected', 'redact', 'global')
ON CONFLICT (policy_id) DO NOTHING;

-- Insert essential default dynamic policies
INSERT INTO dynamic_policies (policy_id, name, description, policy_type, risk_threshold, conditions, actions, priority, tenant_id) VALUES
('high_risk_block', 'Block High-Risk Queries', 'Block queries with risk score above safety threshold', 'risk_based', 0.8,
    '[{"field": "risk_score", "operator": "greater_than", "value": 0.8}]',
    '[{"type": "block", "config": {"reason": "Query risk score exceeds safety threshold"}}]',
    1000, 'global'),
('sensitive_data_control', 'Control Sensitive Data Access', 'Redact sensitive data fields in responses', 'context_aware', 0.5,
    '[{"field": "query", "operator": "contains", "value": "salary|ssn|medical_record"}]',
    '[{"type": "redact", "config": {"fields": ["salary", "ssn", "medical_record"]}}]',
    900, 'global')
ON CONFLICT (policy_id) DO NOTHING;

-- Migration complete
-- Next: 015_audit_logs.sql
