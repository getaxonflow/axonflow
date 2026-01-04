-- Cost Controls: Budget limits and usage tracking
-- Migration: 034_cost_controls.sql

-- Budget definitions
CREATE TABLE IF NOT EXISTS budgets (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    scope VARCHAR(50) NOT NULL CHECK (scope IN ('organization', 'team', 'agent', 'workflow', 'user')),
    scope_id VARCHAR(255),
    limit_usd DECIMAL(12, 2) NOT NULL CHECK (limit_usd > 0),
    period VARCHAR(20) NOT NULL CHECK (period IN ('daily', 'weekly', 'monthly', 'quarterly', 'yearly')),
    on_exceed VARCHAR(50) DEFAULT 'warn' CHECK (on_exceed IN ('warn', 'block', 'downgrade')),
    alert_thresholds JSONB DEFAULT '[50, 80, 100]',
    enabled BOOLEAN DEFAULT true,

    -- Multi-tenant support
    org_id VARCHAR(255),
    tenant_id VARCHAR(255),

    -- Audit
    created_by VARCHAR(255),
    updated_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for budget queries
CREATE INDEX IF NOT EXISTS idx_budgets_scope ON budgets(scope, scope_id);
CREATE INDEX IF NOT EXISTS idx_budgets_org ON budgets(org_id);
CREATE INDEX IF NOT EXISTS idx_budgets_tenant ON budgets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_budgets_enabled ON budgets(enabled);

-- Usage tracking (per request)
CREATE TABLE IF NOT EXISTS usage_records (
    id BIGSERIAL PRIMARY KEY,
    request_id VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Attribution (who used it)
    org_id VARCHAR(255),
    tenant_id VARCHAR(255),
    team_id VARCHAR(255),
    agent_id VARCHAR(255),
    workflow_id VARCHAR(255),
    user_id VARCHAR(255),

    -- Usage details
    provider VARCHAR(100) NOT NULL,
    model VARCHAR(100) NOT NULL,
    tokens_in INTEGER NOT NULL CHECK (tokens_in >= 0),
    tokens_out INTEGER NOT NULL CHECK (tokens_out >= 0),

    -- Cost
    cost_usd DECIMAL(12, 6) NOT NULL CHECK (cost_usd >= 0),

    -- Request metadata
    request_type VARCHAR(50), -- completion, embedding, etc.
    cached BOOLEAN DEFAULT false,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for usage queries
CREATE INDEX IF NOT EXISTS idx_usage_request ON usage_records(request_id);
CREATE INDEX IF NOT EXISTS idx_usage_org_time ON usage_records(org_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_usage_tenant_time ON usage_records(tenant_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_usage_team_time ON usage_records(team_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_usage_agent_time ON usage_records(agent_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_usage_user_time ON usage_records(user_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_usage_provider ON usage_records(provider, timestamp);
CREATE INDEX IF NOT EXISTS idx_usage_model ON usage_records(model, timestamp);
CREATE INDEX IF NOT EXISTS idx_usage_timestamp ON usage_records(timestamp);

-- Usage aggregates (for fast queries and dashboards)
CREATE TABLE IF NOT EXISTS usage_aggregates (
    id BIGSERIAL PRIMARY KEY,
    scope VARCHAR(50) NOT NULL CHECK (scope IN ('organization', 'team', 'agent', 'workflow', 'user', 'provider', 'model')),
    scope_id VARCHAR(255) NOT NULL,
    period VARCHAR(20) NOT NULL CHECK (period IN ('hourly', 'daily', 'weekly', 'monthly')),
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Aggregated metrics
    total_cost_usd DECIMAL(12, 2) DEFAULT 0,
    total_tokens_in INTEGER DEFAULT 0,
    total_tokens_out INTEGER DEFAULT 0,
    request_count INTEGER DEFAULT 0,

    -- Attribution for joins
    org_id VARCHAR(255),
    tenant_id VARCHAR(255),

    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(scope, scope_id, period, period_start, org_id, tenant_id)
);

-- Indexes for aggregate queries
CREATE INDEX IF NOT EXISTS idx_aggregates_lookup ON usage_aggregates(scope, scope_id, period, period_start);
CREATE INDEX IF NOT EXISTS idx_aggregates_org ON usage_aggregates(org_id, period, period_start);
CREATE INDEX IF NOT EXISTS idx_aggregates_tenant ON usage_aggregates(tenant_id, period, period_start);

-- Budget alerts (for tracking sent alerts)
CREATE TABLE IF NOT EXISTS budget_alerts (
    id BIGSERIAL PRIMARY KEY,
    budget_id VARCHAR(255) NOT NULL REFERENCES budgets(id) ON DELETE CASCADE,
    threshold INTEGER NOT NULL,
    percentage_reached DECIMAL(5, 2) NOT NULL,
    amount_usd DECIMAL(12, 2) NOT NULL,
    alert_type VARCHAR(50) NOT NULL CHECK (alert_type IN ('threshold_reached', 'budget_exceeded', 'budget_blocked')),
    message TEXT,
    acknowledged BOOLEAN DEFAULT false,
    acknowledged_by VARCHAR(255),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for alerts
CREATE INDEX IF NOT EXISTS idx_alerts_budget ON budget_alerts(budget_id, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_unack ON budget_alerts(acknowledged, created_at) WHERE NOT acknowledged;

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_budget_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for budgets updated_at
DROP TRIGGER IF EXISTS trigger_budget_updated_at ON budgets;
CREATE TRIGGER trigger_budget_updated_at
    BEFORE UPDATE ON budgets
    FOR EACH ROW
    EXECUTE FUNCTION update_budget_updated_at();
