-- Migration 007: Runtime Connector and LLM Provider Configuration
-- Date: 2025-11-28
-- ADR Reference: ADR-007-RUNTIME_CONNECTOR_CONFIGURATION.md
-- Purpose: Enable runtime configuration of MCP connectors and LLM providers
--          without requiring infrastructure redeployment. Enterprise customers
--          manage configuration through Customer Portal; OSS users via config files.

-- ============================================================
-- 1. Helper Function for updated_at Trigger
-- ============================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION update_updated_at_column IS 'Automatically updates updated_at timestamp on row modification';

-- ============================================================
-- 2. Connector Configurations Table (Agent - MCP Connectors)
-- ============================================================
-- Stores configuration for MCP connectors (postgres, cassandra, salesforce, amadeus, slack, snowflake)
-- Replaces environment variable-based configuration for enterprise deployments

CREATE TABLE connector_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(100) NOT NULL REFERENCES customers(tenant_id) ON DELETE CASCADE,

    -- Connector identification
    connector_name VARCHAR(100) NOT NULL,
    connector_type VARCHAR(50) NOT NULL,  -- 'postgres', 'cassandra', 'salesforce', 'amadeus', 'slack', 'snowflake'
    display_name VARCHAR(255),
    description TEXT,

    -- Connection details (non-sensitive stored directly)
    connection_url VARCHAR(500),
    options JSONB DEFAULT '{}',  -- Non-sensitive options (e.g., {"schema": "public", "ssl_mode": "verify-full"})

    -- Credential reference (sensitive data in Secrets Manager)
    credentials_secret_arn VARCHAR(500),  -- AWS Secrets Manager ARN
    credentials_secret_version VARCHAR(100),  -- Optional version ID for pinning

    -- Connector behavior
    timeout_ms INTEGER DEFAULT 30000,
    max_retries INTEGER DEFAULT 3,

    -- Status
    enabled BOOLEAN DEFAULT true,
    health_status VARCHAR(20) DEFAULT 'unknown',  -- 'healthy', 'unhealthy', 'unknown'
    last_health_check TIMESTAMPTZ,
    last_error TEXT,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(100),
    updated_by VARCHAR(100),

    -- Constraints
    UNIQUE(tenant_id, connector_name),
    CONSTRAINT check_connector_type CHECK (connector_type IN (
        'postgres', 'cassandra', 'salesforce', 'amadeus', 'slack', 'snowflake', 'custom'
    )),
    CONSTRAINT check_health_status CHECK (health_status IN ('healthy', 'unhealthy', 'unknown'))
);

-- Indexes for connector_configs
CREATE INDEX idx_connector_configs_tenant ON connector_configs(tenant_id);
CREATE INDEX idx_connector_configs_type ON connector_configs(connector_type);
CREATE INDEX idx_connector_configs_enabled ON connector_configs(tenant_id) WHERE enabled = true;
CREATE INDEX idx_connector_configs_health ON connector_configs(health_status) WHERE enabled = true;

-- Trigger for updated_at
CREATE TRIGGER connector_configs_updated_at
    BEFORE UPDATE ON connector_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE connector_configs IS 'Runtime configuration for MCP connectors. Credentials stored in AWS Secrets Manager.';
COMMENT ON COLUMN connector_configs.connector_type IS 'Type of connector: postgres, cassandra, salesforce, amadeus, slack, snowflake, custom';
COMMENT ON COLUMN connector_configs.credentials_secret_arn IS 'AWS Secrets Manager ARN containing sensitive credentials';
COMMENT ON COLUMN connector_configs.options IS 'Non-sensitive configuration options as JSON';

-- ============================================================
-- 3. LLM Provider Configurations Table (Orchestrator)
-- ============================================================
-- Stores configuration for LLM providers (bedrock, ollama, openai, anthropic)
-- Supports routing weights for load balancing and failover

CREATE TABLE llm_provider_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(100) NOT NULL REFERENCES customers(tenant_id) ON DELETE CASCADE,

    -- Provider identification
    provider_name VARCHAR(50) NOT NULL,  -- 'bedrock', 'ollama', 'openai', 'anthropic'
    display_name VARCHAR(255),

    -- Provider-specific configuration (non-sensitive)
    config JSONB NOT NULL DEFAULT '{}',
    -- For Bedrock: {"region": "us-east-1", "model": "anthropic.claude-3-5-sonnet-20240620-v1:0"}
    -- For Ollama: {"endpoint": "http://ollama:11434", "model": "llama3.1:70b"}
    -- For OpenAI: {"model": "gpt-4-turbo", "max_tokens": 4096}
    -- For Anthropic: {"model": "claude-3-5-sonnet-20241022", "max_tokens": 8192}

    -- Credential reference (API keys in Secrets Manager)
    credentials_secret_arn VARCHAR(500),

    -- Routing configuration
    priority INTEGER DEFAULT 0,  -- Higher = preferred (used for failover ordering)
    weight NUMERIC(3,2) DEFAULT 1.00,  -- For load balancing (0.00-1.00)

    -- Status
    enabled BOOLEAN DEFAULT true,
    health_status VARCHAR(20) DEFAULT 'unknown',  -- 'healthy', 'unhealthy', 'unknown'
    last_health_check TIMESTAMPTZ,
    last_error TEXT,

    -- Cost tracking (optional, for routing decisions)
    cost_per_1k_input_tokens NUMERIC(10,6),
    cost_per_1k_output_tokens NUMERIC(10,6),

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(100),
    updated_by VARCHAR(100),

    -- Constraints
    UNIQUE(tenant_id, provider_name),
    CONSTRAINT check_provider_name CHECK (provider_name IN ('bedrock', 'ollama', 'openai', 'anthropic')),
    CONSTRAINT check_llm_health_status CHECK (health_status IN ('healthy', 'unhealthy', 'unknown')),
    CONSTRAINT check_weight_range CHECK (weight >= 0.00 AND weight <= 1.00)
);

-- Indexes for llm_provider_configs
CREATE INDEX idx_llm_provider_configs_tenant ON llm_provider_configs(tenant_id);
CREATE INDEX idx_llm_provider_configs_enabled ON llm_provider_configs(tenant_id) WHERE enabled = true;
CREATE INDEX idx_llm_provider_configs_priority ON llm_provider_configs(tenant_id, priority DESC) WHERE enabled = true;

-- Trigger for updated_at
CREATE TRIGGER llm_provider_configs_updated_at
    BEFORE UPDATE ON llm_provider_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE llm_provider_configs IS 'Runtime configuration for LLM providers. Supports routing with priority and weight.';
COMMENT ON COLUMN llm_provider_configs.config IS 'Provider-specific configuration as JSON (region, model, endpoint, etc.)';
COMMENT ON COLUMN llm_provider_configs.priority IS 'Higher value = higher priority. Used for failover ordering.';
COMMENT ON COLUMN llm_provider_configs.weight IS 'Load balancing weight (0.00-1.00). Used for distributing requests.';

-- ============================================================
-- 4. Configuration Audit Log
-- ============================================================
-- Tracks all configuration changes for compliance and debugging

CREATE TABLE config_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(100) NOT NULL,

    -- What changed
    config_type VARCHAR(50) NOT NULL,  -- 'connector', 'llm_provider'
    config_id UUID NOT NULL,
    config_name VARCHAR(100) NOT NULL,

    -- Change details
    action VARCHAR(20) NOT NULL,  -- 'create', 'update', 'delete', 'enable', 'disable', 'test'
    previous_value JSONB,
    new_value JSONB,
    changed_fields TEXT[],  -- Array of field names that changed

    -- Who changed it
    changed_by VARCHAR(100) NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source VARCHAR(50) NOT NULL,  -- 'customer_portal', 'api', 'config_file', 'migration'

    -- Request correlation
    request_id VARCHAR(100),
    ip_address INET,

    -- Constraints
    CONSTRAINT check_config_type CHECK (config_type IN ('connector', 'llm_provider')),
    CONSTRAINT check_action CHECK (action IN ('create', 'update', 'delete', 'enable', 'disable', 'test'))
);

-- Indexes for config_audit_log
CREATE INDEX idx_config_audit_log_tenant ON config_audit_log(tenant_id, changed_at DESC);
CREATE INDEX idx_config_audit_log_config ON config_audit_log(config_id, changed_at DESC);
CREATE INDEX idx_config_audit_log_type ON config_audit_log(config_type, changed_at DESC);

COMMENT ON TABLE config_audit_log IS 'Audit trail for all connector and LLM provider configuration changes';
COMMENT ON COLUMN config_audit_log.source IS 'Origin of the change: customer_portal, api, config_file, or migration';
COMMENT ON COLUMN config_audit_log.changed_fields IS 'List of field names that were modified in this change';

-- ============================================================
-- 5. Dangerous Operations Configuration Table
-- ============================================================
-- Defines which operations are blocked by default for each connector type
-- Can be customized per tenant for specific use cases

CREATE TABLE connector_dangerous_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(100) REFERENCES customers(tenant_id) ON DELETE CASCADE,  -- NULL for global defaults
    connector_type VARCHAR(50) NOT NULL,
    blocked_operations TEXT[] NOT NULL,  -- Array of blocked operation patterns
    allow_override BOOLEAN DEFAULT false,  -- Can tenant override these?
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, connector_type)
);

-- Insert global defaults for dangerous operations
INSERT INTO connector_dangerous_operations (tenant_id, connector_type, blocked_operations, allow_override) VALUES
    (NULL, 'postgres', ARRAY['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'GRANT', 'REVOKE'], false),
    (NULL, 'cassandra', ARRAY['DROP', 'TRUNCATE', 'ALTER'], false),
    (NULL, 'snowflake', ARRAY['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'GRANT', 'REVOKE'], false),
    (NULL, 'salesforce', ARRAY['DELETE', 'PURGE'], true),
    (NULL, 'slack', ARRAY['DELETE'], true),
    (NULL, 'amadeus', ARRAY[], true);  -- No dangerous operations by default

CREATE INDEX idx_dangerous_ops_lookup ON connector_dangerous_operations(connector_type, tenant_id);

CREATE TRIGGER connector_dangerous_ops_updated_at
    BEFORE UPDATE ON connector_dangerous_operations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE connector_dangerous_operations IS 'Defines blocked operations per connector type. NULL tenant_id = global defaults.';
COMMENT ON COLUMN connector_dangerous_operations.allow_override IS 'If true, tenants can customize blocked operations for this connector type';

-- ============================================================
-- 6. Helper Functions
-- ============================================================

-- Function to get effective connector config (merges tenant config with defaults)
CREATE OR REPLACE FUNCTION get_connector_config(
    p_tenant_id VARCHAR(100),
    p_connector_name VARCHAR(100)
) RETURNS TABLE (
    id UUID,
    tenant_id VARCHAR(100),
    connector_name VARCHAR(100),
    connector_type VARCHAR(50),
    connection_url VARCHAR(500),
    options JSONB,
    credentials_secret_arn VARCHAR(500),
    timeout_ms INTEGER,
    max_retries INTEGER,
    enabled BOOLEAN,
    blocked_operations TEXT[]
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        cc.id,
        cc.tenant_id,
        cc.connector_name,
        cc.connector_type,
        cc.connection_url,
        cc.options,
        cc.credentials_secret_arn,
        cc.timeout_ms,
        cc.max_retries,
        cc.enabled,
        COALESCE(
            cdo_tenant.blocked_operations,
            cdo_global.blocked_operations,
            ARRAY[]::TEXT[]
        ) as blocked_operations
    FROM connector_configs cc
    LEFT JOIN connector_dangerous_operations cdo_tenant
        ON cc.connector_type = cdo_tenant.connector_type
        AND cc.tenant_id = cdo_tenant.tenant_id
    LEFT JOIN connector_dangerous_operations cdo_global
        ON cc.connector_type = cdo_global.connector_type
        AND cdo_global.tenant_id IS NULL
    WHERE cc.tenant_id = p_tenant_id
    AND cc.connector_name = p_connector_name
    AND cc.enabled = true;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_connector_config IS 'Returns connector config with merged dangerous operations (tenant overrides global)';

-- Function to get all enabled LLM providers for a tenant, ordered by priority
CREATE OR REPLACE FUNCTION get_llm_providers(
    p_tenant_id VARCHAR(100)
) RETURNS TABLE (
    id UUID,
    provider_name VARCHAR(50),
    config JSONB,
    credentials_secret_arn VARCHAR(500),
    priority INTEGER,
    weight NUMERIC(3,2),
    health_status VARCHAR(20)
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        lpc.id,
        lpc.provider_name,
        lpc.config,
        lpc.credentials_secret_arn,
        lpc.priority,
        lpc.weight,
        lpc.health_status
    FROM llm_provider_configs lpc
    WHERE lpc.tenant_id = p_tenant_id
    AND lpc.enabled = true
    ORDER BY lpc.priority DESC, lpc.weight DESC;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_llm_providers IS 'Returns enabled LLM providers for a tenant, ordered by priority and weight';

-- Function to log configuration changes
CREATE OR REPLACE FUNCTION log_config_change(
    p_tenant_id VARCHAR(100),
    p_config_type VARCHAR(50),
    p_config_id UUID,
    p_config_name VARCHAR(100),
    p_action VARCHAR(20),
    p_previous_value JSONB,
    p_new_value JSONB,
    p_changed_by VARCHAR(100),
    p_source VARCHAR(50),
    p_request_id VARCHAR(100) DEFAULT NULL,
    p_ip_address INET DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_changed_fields TEXT[];
    v_log_id UUID;
BEGIN
    -- Calculate changed fields if both values exist
    IF p_previous_value IS NOT NULL AND p_new_value IS NOT NULL THEN
        SELECT array_agg(key)
        INTO v_changed_fields
        FROM (
            SELECT key FROM jsonb_object_keys(p_previous_value) AS key
            WHERE p_previous_value->key IS DISTINCT FROM p_new_value->key
            UNION
            SELECT key FROM jsonb_object_keys(p_new_value) AS key
            WHERE NOT p_previous_value ? key
        ) changed_keys;
    END IF;

    INSERT INTO config_audit_log (
        tenant_id, config_type, config_id, config_name, action,
        previous_value, new_value, changed_fields,
        changed_by, source, request_id, ip_address
    ) VALUES (
        p_tenant_id, p_config_type, p_config_id, p_config_name, p_action,
        p_previous_value, p_new_value, v_changed_fields,
        p_changed_by, p_source, p_request_id, p_ip_address
    ) RETURNING id INTO v_log_id;

    RETURN v_log_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION log_config_change IS 'Creates an audit log entry for configuration changes with automatic field change detection';

-- ============================================================
-- 7. Seed Data for Existing Tenants (Migration)
-- ============================================================
-- Create default LLM provider configs for existing tenants using Bedrock
-- This ensures backward compatibility with existing deployments

INSERT INTO llm_provider_configs (
    tenant_id,
    provider_name,
    display_name,
    config,
    priority,
    weight,
    enabled,
    created_by
)
SELECT
    c.tenant_id,
    'bedrock',
    'Amazon Bedrock (Default)',
    jsonb_build_object(
        'region', COALESCE(current_setting('app.bedrock_region', true), 'us-east-1'),
        'model', COALESCE(current_setting('app.bedrock_model', true), 'anthropic.claude-3-5-sonnet-20240620-v1:0')
    ),
    10,  -- High priority as primary provider
    1.00,
    true,
    'migration_007'
FROM customers c
WHERE c.status = 'active'
AND NOT EXISTS (
    SELECT 1 FROM llm_provider_configs lpc WHERE lpc.tenant_id = c.tenant_id
)
ON CONFLICT (tenant_id, provider_name) DO NOTHING;

-- Log the migration
INSERT INTO config_audit_log (tenant_id, config_type, config_id, config_name, action, new_value, changed_by, source)
SELECT
    lpc.tenant_id,
    'llm_provider',
    lpc.id,
    lpc.provider_name,
    'create',
    to_jsonb(lpc) - 'id' - 'created_at' - 'updated_at',
    'migration_007',
    'migration'
FROM llm_provider_configs lpc
WHERE lpc.created_by = 'migration_007';

-- ============================================================
-- Comments for Documentation
-- ============================================================
COMMENT ON TABLE connector_configs IS 'Runtime configuration for MCP connectors. Priority: Database > Config File > Environment Variables.';
COMMENT ON TABLE llm_provider_configs IS 'Runtime configuration for LLM providers with routing weights and priority.';
COMMENT ON TABLE config_audit_log IS 'Immutable audit trail for all configuration changes. Required for compliance.';
COMMENT ON TABLE connector_dangerous_operations IS 'Security controls: operations blocked by default per connector type.';
