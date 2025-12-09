-- Migration 021: Runtime Connector and LLM Provider Configuration
-- Date: 2025-11-28
-- ADR Reference: ADR-007-RUNTIME_CONNECTOR_CONFIGURATION.md
-- Purpose: Enable runtime configuration of MCP connectors and LLM providers
--          without requiring infrastructure redeployment. Enterprise customers
--          manage configuration through Customer Portal; OSS users via config files.
-- Note: This migration is CONDITIONAL - it only runs if customers table exists
--       The customers table is created by ee/migrations/ (Enterprise only)
--       OSS deployments without Enterprise will skip this migration gracefully

-- =============================================================================
-- Conditional Migration - Only runs if customers table exists
-- =============================================================================

DO $migration$
DECLARE
    customers_exists BOOLEAN;
BEGIN
    -- Check if customers table exists (created by Enterprise migration)
    SELECT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'customers'
    ) INTO customers_exists;

    IF NOT customers_exists THEN
        RAISE NOTICE 'Migration 021: customers table does not exist (OSS mode). Skipping.';
        RETURN;
    END IF;

    RAISE NOTICE 'Migration 021: customers table found. Applying runtime connector configuration...';

    -- ============================================================
    -- 1. Helper Function for updated_at Trigger
    -- ============================================================
    EXECUTE $func$
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $body$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $body$ LANGUAGE plpgsql
    $func$;

    -- ============================================================
    -- 2. Connector Configurations Table (Agent - MCP Connectors)
    -- ============================================================
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'connector_configs') THEN
        EXECUTE $table$
            CREATE TABLE connector_configs (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id VARCHAR(100) NOT NULL REFERENCES customers(tenant_id) ON DELETE CASCADE,
                connector_name VARCHAR(100) NOT NULL,
                connector_type VARCHAR(50) NOT NULL,
                display_name VARCHAR(255),
                description TEXT,
                connection_url VARCHAR(500),
                options JSONB DEFAULT '{}',
                credentials_secret_arn VARCHAR(500),
                credentials_secret_version VARCHAR(100),
                timeout_ms INTEGER DEFAULT 30000,
                max_retries INTEGER DEFAULT 3,
                enabled BOOLEAN DEFAULT true,
                health_status VARCHAR(20) DEFAULT 'unknown',
                last_health_check TIMESTAMPTZ,
                last_error TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_by VARCHAR(100),
                updated_by VARCHAR(100),
                UNIQUE(tenant_id, connector_name),
                CONSTRAINT check_connector_type CHECK (connector_type IN (
                    'postgres', 'cassandra', 'salesforce', 'amadeus', 'slack', 'snowflake', 'custom'
                )),
                CONSTRAINT check_health_status CHECK (health_status IN ('healthy', 'unhealthy', 'unknown'))
            )
        $table$;
        RAISE NOTICE 'Created table: connector_configs';

        CREATE INDEX idx_connector_configs_tenant ON connector_configs(tenant_id);
        CREATE INDEX idx_connector_configs_type ON connector_configs(connector_type);
        CREATE INDEX idx_connector_configs_enabled ON connector_configs(tenant_id) WHERE enabled = true;
        CREATE INDEX idx_connector_configs_health ON connector_configs(health_status) WHERE enabled = true;

        CREATE TRIGGER connector_configs_updated_at
            BEFORE UPDATE ON connector_configs
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;

    -- ============================================================
    -- 3. LLM Provider Configurations Table (Orchestrator)
    -- ============================================================
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'llm_provider_configs') THEN
        EXECUTE $table$
            CREATE TABLE llm_provider_configs (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id VARCHAR(100) NOT NULL REFERENCES customers(tenant_id) ON DELETE CASCADE,
                provider_name VARCHAR(50) NOT NULL,
                display_name VARCHAR(255),
                config JSONB NOT NULL DEFAULT '{}',
                credentials_secret_arn VARCHAR(500),
                priority INTEGER DEFAULT 0,
                weight NUMERIC(3,2) DEFAULT 1.00,
                enabled BOOLEAN DEFAULT true,
                health_status VARCHAR(20) DEFAULT 'unknown',
                last_health_check TIMESTAMPTZ,
                last_error TEXT,
                cost_per_1k_input_tokens NUMERIC(10,6),
                cost_per_1k_output_tokens NUMERIC(10,6),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_by VARCHAR(100),
                updated_by VARCHAR(100),
                UNIQUE(tenant_id, provider_name),
                CONSTRAINT check_provider_name CHECK (provider_name IN ('bedrock', 'ollama', 'openai', 'anthropic')),
                CONSTRAINT check_llm_health_status CHECK (health_status IN ('healthy', 'unhealthy', 'unknown')),
                CONSTRAINT check_weight_range CHECK (weight >= 0.00 AND weight <= 1.00)
            )
        $table$;
        RAISE NOTICE 'Created table: llm_provider_configs';

        CREATE INDEX idx_llm_provider_configs_tenant ON llm_provider_configs(tenant_id);
        CREATE INDEX idx_llm_provider_configs_enabled ON llm_provider_configs(tenant_id) WHERE enabled = true;
        CREATE INDEX idx_llm_provider_configs_priority ON llm_provider_configs(tenant_id, priority DESC) WHERE enabled = true;

        CREATE TRIGGER llm_provider_configs_updated_at
            BEFORE UPDATE ON llm_provider_configs
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;

    -- ============================================================
    -- 4. Configuration Audit Log
    -- ============================================================
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'config_audit_log') THEN
        EXECUTE $table$
            CREATE TABLE config_audit_log (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id VARCHAR(100) NOT NULL,
                config_type VARCHAR(50) NOT NULL,
                config_id UUID NOT NULL,
                config_name VARCHAR(100) NOT NULL,
                action VARCHAR(20) NOT NULL,
                previous_value JSONB,
                new_value JSONB,
                changed_fields TEXT[],
                changed_by VARCHAR(100) NOT NULL,
                changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                source VARCHAR(50) NOT NULL,
                request_id VARCHAR(100),
                ip_address INET,
                CONSTRAINT check_config_type CHECK (config_type IN ('connector', 'llm_provider')),
                CONSTRAINT check_action CHECK (action IN ('create', 'update', 'delete', 'enable', 'disable', 'test'))
            )
        $table$;
        RAISE NOTICE 'Created table: config_audit_log';

        CREATE INDEX idx_config_audit_log_tenant ON config_audit_log(tenant_id, changed_at DESC);
        CREATE INDEX idx_config_audit_log_config ON config_audit_log(config_id, changed_at DESC);
        CREATE INDEX idx_config_audit_log_type ON config_audit_log(config_type, changed_at DESC);
    END IF;

    -- ============================================================
    -- 5. Dangerous Operations Configuration Table
    -- ============================================================
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'connector_dangerous_operations') THEN
        EXECUTE $table$
            CREATE TABLE connector_dangerous_operations (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id VARCHAR(100) REFERENCES customers(tenant_id) ON DELETE CASCADE,
                connector_type VARCHAR(50) NOT NULL,
                blocked_operations TEXT[] NOT NULL,
                allow_override BOOLEAN DEFAULT false,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(tenant_id, connector_type)
            )
        $table$;
        RAISE NOTICE 'Created table: connector_dangerous_operations';

        -- Insert global defaults for dangerous operations
        INSERT INTO connector_dangerous_operations (tenant_id, connector_type, blocked_operations, allow_override) VALUES
            (NULL, 'postgres', ARRAY['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'GRANT', 'REVOKE'], false),
            (NULL, 'cassandra', ARRAY['DROP', 'TRUNCATE', 'ALTER'], false),
            (NULL, 'snowflake', ARRAY['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'GRANT', 'REVOKE'], false),
            (NULL, 'salesforce', ARRAY['DELETE', 'PURGE'], true),
            (NULL, 'slack', ARRAY['DELETE'], true),
            (NULL, 'amadeus', ARRAY[]::TEXT[], true);

        CREATE INDEX idx_dangerous_ops_lookup ON connector_dangerous_operations(connector_type, tenant_id);

        CREATE TRIGGER connector_dangerous_ops_updated_at
            BEFORE UPDATE ON connector_dangerous_operations
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;

    RAISE NOTICE 'Migration 021 completed successfully';

END $migration$;

-- ============================================================
-- 6. Helper Functions (outside DO block for better compatibility)
-- ============================================================

-- Function to get effective connector config (only if tables exist)
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
    -- Return empty if tables don't exist (OSS mode)
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'connector_configs') THEN
        RETURN;
    END IF;

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

-- Function to get all enabled LLM providers for a tenant
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
    -- Return empty if table doesn't exist (OSS mode)
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'llm_provider_configs') THEN
        RETURN;
    END IF;

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
    -- Return NULL if table doesn't exist (OSS mode)
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'config_audit_log') THEN
        RETURN NULL;
    END IF;

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

-- Comments for Documentation
COMMENT ON FUNCTION get_connector_config IS 'Returns connector config with merged dangerous operations (tenant overrides global). Returns empty in OSS mode.';
COMMENT ON FUNCTION get_llm_providers IS 'Returns enabled LLM providers for a tenant, ordered by priority and weight. Returns empty in OSS mode.';
COMMENT ON FUNCTION log_config_change IS 'Creates an audit log entry for configuration changes. Returns NULL in OSS mode.';
