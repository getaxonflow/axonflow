-- Migration 027: LLM Provider Registry
-- Enables pluggable LLM provider configuration per organization
-- Part of Epic #360: Refactor LLM providers to be pluggable

-- LLM providers configuration table
CREATE TABLE IF NOT EXISTS llm_providers (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'openai', 'anthropic', 'bedrock', 'ollama', 'gemini', 'custom'

    -- Authentication
    api_key_encrypted TEXT, -- Encrypted API key (use for non-production)
    api_key_secret_arn VARCHAR(500), -- AWS Secrets Manager ARN (production)

    -- Configuration
    endpoint VARCHAR(500), -- Custom API endpoint URL
    model VARCHAR(200), -- Default model
    region VARCHAR(50), -- AWS region for Bedrock

    -- Routing configuration
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 0, -- Higher = more preferred
    weight INTEGER DEFAULT 0 CHECK (weight >= 0 AND weight <= 100), -- For weighted routing
    rate_limit INTEGER DEFAULT 0, -- Requests per minute (0 = unlimited)
    timeout_seconds INTEGER DEFAULT 30 CHECK (timeout_seconds >= 0),

    -- Provider-specific settings
    settings JSONB DEFAULT '{}'::jsonb,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255),
    updated_by VARCHAR(255),

    -- Constraints
    CONSTRAINT uq_llm_providers_tenant_name UNIQUE(tenant_id, name),
    CONSTRAINT chk_llm_provider_type CHECK (type IN ('openai', 'anthropic', 'bedrock', 'ollama', 'gemini', 'custom')),
    CONSTRAINT chk_llm_priority_non_negative CHECK (priority >= 0)
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_llm_providers_tenant_id ON llm_providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_llm_providers_type ON llm_providers(type);
CREATE INDEX IF NOT EXISTS idx_llm_providers_enabled ON llm_providers(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_llm_providers_priority ON llm_providers(tenant_id, priority DESC);

-- Row Level Security (RLS)
-- Uses app.current_org_id to match existing RLS middleware
ALTER TABLE llm_providers ENABLE ROW LEVEL SECURITY;

CREATE POLICY llm_providers_tenant_isolation ON llm_providers
    USING (tenant_id = current_setting('app.current_org_id', true));

-- Update trigger for updated_at
CREATE OR REPLACE FUNCTION update_llm_providers_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_llm_providers_updated_at
    BEFORE UPDATE ON llm_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_llm_providers_updated_at();

-- Provider usage tracking (for analytics and rate limiting)
CREATE TABLE IF NOT EXISTS llm_provider_usage (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id VARCHAR(255) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,

    -- Request tracking
    request_id VARCHAR(255),
    model VARCHAR(200),

    -- Token usage
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,

    -- Cost tracking
    estimated_cost_usd DECIMAL(10, 6) DEFAULT 0,

    -- Performance metrics
    latency_ms INTEGER,
    status VARCHAR(50), -- 'success', 'error', 'timeout', 'rate_limited'
    error_message TEXT,

    -- Timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_llm_provider_usage_provider
        FOREIGN KEY (provider_id)
        REFERENCES llm_providers(id)
        ON DELETE CASCADE
);

-- Indexes for usage table
CREATE INDEX IF NOT EXISTS idx_llm_provider_usage_tenant_id ON llm_provider_usage(tenant_id);
CREATE INDEX IF NOT EXISTS idx_llm_provider_usage_provider_id ON llm_provider_usage(provider_id);
CREATE INDEX IF NOT EXISTS idx_llm_provider_usage_created_at ON llm_provider_usage(created_at);
CREATE INDEX IF NOT EXISTS idx_llm_provider_usage_status ON llm_provider_usage(status);

-- Time-based partitioning hint: usage table can be partitioned by created_at for scale
-- PARTITION BY RANGE (created_at);

-- RLS for usage table
ALTER TABLE llm_provider_usage ENABLE ROW LEVEL SECURITY;

CREATE POLICY llm_provider_usage_tenant_isolation ON llm_provider_usage
    USING (tenant_id = current_setting('app.current_org_id', true));

-- Provider health status tracking
CREATE TABLE IF NOT EXISTS llm_provider_health (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    provider_id VARCHAR(255) NOT NULL UNIQUE,

    -- Health status
    status VARCHAR(20) NOT NULL DEFAULT 'unknown', -- 'healthy', 'degraded', 'unhealthy', 'unknown'
    message TEXT,
    latency_ms INTEGER,

    -- Tracking
    last_checked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    consecutive_failures INTEGER DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_llm_provider_health_provider
        FOREIGN KEY (provider_id)
        REFERENCES llm_providers(id)
        ON DELETE CASCADE,
    CONSTRAINT chk_health_status CHECK (status IN ('healthy', 'degraded', 'unhealthy', 'unknown'))
);

-- Index for health lookups
CREATE INDEX IF NOT EXISTS idx_llm_provider_health_status ON llm_provider_health(status);
CREATE INDEX IF NOT EXISTS idx_llm_provider_health_last_checked ON llm_provider_health(last_checked_at);

-- Insert default providers for existing tenants (Anthropic from env vars)
-- Note: Actual API key should be set via UPDATE after migration
-- This creates placeholder entries that can be updated via the API
INSERT INTO llm_providers (id, tenant_id, name, type, model, enabled, priority)
SELECT
    'provider_anthropic_' || tenant_id,
    tenant_id,
    'anthropic-default',
    'anthropic',
    'claude-sonnet-4-20250514',
    true,
    100
FROM (SELECT DISTINCT tenant_id FROM dynamic_policies WHERE tenant_id IS NOT NULL) AS tenants
ON CONFLICT (tenant_id, name) DO NOTHING;

-- Comments
COMMENT ON TABLE llm_providers IS 'LLM provider configurations per organization for pluggable provider support';
COMMENT ON TABLE llm_provider_usage IS 'Request-level usage tracking for LLM providers';
COMMENT ON TABLE llm_provider_health IS 'Health status tracking for LLM providers';
COMMENT ON COLUMN llm_providers.api_key_encrypted IS 'Encrypted API key - use api_key_secret_arn in production';
COMMENT ON COLUMN llm_providers.api_key_secret_arn IS 'AWS Secrets Manager ARN for production API key storage';
COMMENT ON COLUMN llm_providers.settings IS 'Provider-specific configuration as JSON';
COMMENT ON COLUMN llm_provider_usage.estimated_cost_usd IS 'Estimated cost in USD based on token counts';
