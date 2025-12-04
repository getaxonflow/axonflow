-- Migration 006: Option 3 - Complete Authentication System
-- Date: 2025-10-27
-- Purpose: Database-backed authentication with usage tracking and metered billing

-- ============================================================
-- 1. Pricing Tiers Table
-- ============================================================
CREATE TABLE IF NOT EXISTS pricing_tiers (
    tier VARCHAR(20) NOT NULL,
    deployment_mode VARCHAR(20) NOT NULL, -- 'saas' or 'in-vpc'
    monthly_price INTEGER NOT NULL, -- in cents ($5,000 = 500000)
    included_requests BIGINT, -- NULL for in-vpc mode
    max_nodes INTEGER, -- NULL for saas mode
    max_users INTEGER, -- NULL for unlimited
    requests_per_minute INTEGER NOT NULL, -- rate limit
    overage_rate_per_1k DECIMAL(10,4), -- NULL for in-vpc mode
    support_sla_hours INTEGER NOT NULL,
    features JSONB NOT NULL DEFAULT '{}',
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tier, deployment_mode)
);

-- Insert pricing tiers from updated strategy
INSERT INTO pricing_tiers (tier, deployment_mode, monthly_price, included_requests, max_nodes, max_users, requests_per_minute, overage_rate_per_1k, support_sla_hours, features) VALUES
-- SaaS Mode
('STARTER', 'saas', 500000, 500000, NULL, 5, 2000, 0.1000, 24, '{"sso": false, "rbac": "basic", "email_support": true}'),
('PRO', 'saas', 1500000, 3000000, NULL, 25, 10000, 0.0300, 12, '{"sso": true, "rbac": "standard", "email_support": true}'),
('ENT', 'saas', 5000000, 10000000, NULL, NULL, 30000, 0.0100, 4, '{"sso": true, "rbac": "advanced", "dedicated_environment": true, "priority_support": true, "support_24x7": true}'),

-- In-VPC Mode
('PRO', 'in-vpc', 2000000, NULL, 10, 25, 10000, NULL, 12, '{"sso": true, "rbac": "standard", "email_support": true, "node_based": true}'),
('ENT', 'in-vpc', 6000000, NULL, 50, NULL, 30000, NULL, 4, '{"sso": true, "rbac": "advanced", "priority_support": true, "support_24x7": true, "node_based": true}'),
('PLUS', 'in-vpc', NULL, NULL, NULL, NULL, 100000, NULL, 1, '{"sso": true, "rbac": "advanced", "dedicated_sa": true, "unlimited_nodes": true, "custom_pricing": true, "support_24x7": true}');

-- ============================================================
-- 2. Customers Table
-- ============================================================
CREATE TABLE IF NOT EXISTS customers (
    customer_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_name VARCHAR(255) NOT NULL,
    organization_id VARCHAR(100) NOT NULL UNIQUE, -- e.g., 'acme', 'healthcare'
    deployment_mode VARCHAR(20) NOT NULL, -- 'saas' or 'in-vpc'
    tier VARCHAR(20) NOT NULL,
    tenant_id VARCHAR(100) NOT NULL UNIQUE,

    -- Billing information
    billing_email VARCHAR(255) NOT NULL,
    billing_contact_name VARCHAR(255),
    billing_address JSONB,

    -- Contract information
    contract_start_date DATE NOT NULL,
    contract_end_date DATE,
    auto_renew BOOLEAN NOT NULL DEFAULT true,

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'active', -- 'active', 'suspended', 'cancelled'
    enabled BOOLEAN NOT NULL DEFAULT true,

    -- Metadata
    metadata JSONB DEFAULT '{}',
    notes TEXT,

    -- Audit fields
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(100),
    updated_by VARCHAR(100),

    -- Constraints
    CONSTRAINT fk_pricing_tier FOREIGN KEY (tier, deployment_mode)
        REFERENCES pricing_tiers(tier, deployment_mode),
    CONSTRAINT check_status CHECK (status IN ('active', 'suspended', 'cancelled')),
    CONSTRAINT check_deployment_mode CHECK (deployment_mode IN ('saas', 'in-vpc'))
);

-- Indexes for customers table
CREATE INDEX idx_customers_org_id ON customers(organization_id);
CREATE INDEX idx_customers_tenant_id ON customers(tenant_id);
CREATE INDEX idx_customers_status ON customers(status) WHERE enabled = true;
CREATE INDEX idx_customers_tier ON customers(tier, deployment_mode);

-- ============================================================
-- 3. API Keys Table
-- ============================================================
CREATE TABLE IF NOT EXISTS api_keys (
    api_key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,

    -- License key (stored hashed for security)
    license_key VARCHAR(200) NOT NULL UNIQUE, -- AXON-{TIER}-{ORG}-{EXPIRY}-{SIGNATURE}
    license_key_hash VARCHAR(64) NOT NULL, -- SHA-256 hash for lookup

    -- Key metadata
    key_name VARCHAR(100) NOT NULL, -- Human-readable name
    key_type VARCHAR(20) NOT NULL DEFAULT 'production', -- 'production', 'sandbox', 'test'

    -- Expiration
    expires_at TIMESTAMPTZ NOT NULL,
    grace_period_days INTEGER NOT NULL DEFAULT 7,

    -- Permissions (additional restrictions beyond tier)
    permissions JSONB DEFAULT '["query", "llm"]',
    ip_whitelist INET[], -- NULL = no restriction

    -- Rate limiting overrides (NULL = use tier default)
    custom_rate_limit INTEGER, -- requests per minute

    -- Status
    enabled BOOLEAN NOT NULL DEFAULT true,
    revoked_at TIMESTAMPTZ,
    revoked_by VARCHAR(100),
    revoke_reason TEXT,

    -- Usage tracking
    last_used_at TIMESTAMPTZ,
    total_requests BIGINT NOT NULL DEFAULT 0,

    -- Audit fields
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(100),

    -- Constraints
    CONSTRAINT check_key_type CHECK (key_type IN ('production', 'sandbox', 'test'))
);

-- Indexes for api_keys table
CREATE INDEX idx_api_keys_customer_id ON api_keys(customer_id);
CREATE INDEX idx_api_keys_license_key_hash ON api_keys(license_key_hash);
CREATE INDEX idx_api_keys_enabled ON api_keys(customer_id) WHERE enabled = true AND revoked_at IS NULL;
CREATE INDEX idx_api_keys_expires_at ON api_keys(expires_at) WHERE enabled = true;

-- ============================================================
-- 4. Usage Metrics Table (for metered billing)
-- ============================================================
CREATE TABLE IF NOT EXISTS usage_metrics (
    metric_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,
    api_key_id UUID REFERENCES api_keys(api_key_id) ON DELETE SET NULL,

    -- Time period
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    period_type VARCHAR(20) NOT NULL, -- 'hourly', 'daily', 'monthly'

    -- Usage counts
    total_requests BIGINT NOT NULL DEFAULT 0,
    successful_requests BIGINT NOT NULL DEFAULT 0,
    failed_requests BIGINT NOT NULL DEFAULT 0,
    blocked_requests BIGINT NOT NULL DEFAULT 0,

    -- Request breakdown by type
    query_requests BIGINT NOT NULL DEFAULT 0,
    llm_requests BIGINT NOT NULL DEFAULT 0,
    connector_requests BIGINT NOT NULL DEFAULT 0,
    planning_requests BIGINT NOT NULL DEFAULT 0,

    -- Performance metrics
    avg_latency_ms NUMERIC(10, 2),
    p95_latency_ms NUMERIC(10, 2),
    p99_latency_ms NUMERIC(10, 2),

    -- Billing calculations (for SaaS mode only)
    included_requests BIGINT, -- from tier
    overage_requests BIGINT DEFAULT 0,
    overage_cost_cents INTEGER DEFAULT 0,

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT check_period_type CHECK (period_type IN ('hourly', 'daily', 'monthly')),
    CONSTRAINT check_period_order CHECK (period_end > period_start)
);

-- Indexes for usage_metrics table
CREATE INDEX idx_usage_metrics_customer_period ON usage_metrics(customer_id, period_start DESC);
CREATE INDEX idx_usage_metrics_monthly ON usage_metrics(customer_id, period_type) WHERE period_type = 'monthly';
CREATE INDEX idx_usage_metrics_api_key ON usage_metrics(api_key_id, period_start DESC);
CREATE INDEX idx_usage_metrics_period_start ON usage_metrics(period_start DESC);

-- ============================================================
-- 5. Request Log Table (detailed tracking for debugging/auditing)
-- ============================================================
CREATE TABLE IF NOT EXISTS request_log (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,
    api_key_id UUID REFERENCES api_keys(api_key_id) ON DELETE SET NULL,

    -- Request details
    request_id VARCHAR(100),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    endpoint VARCHAR(100),
    request_type VARCHAR(50),

    -- Response details
    status_code INTEGER,
    latency_ms NUMERIC(10, 2),
    blocked BOOLEAN DEFAULT false,
    block_reason TEXT,

    -- Governance metadata
    policies_evaluated TEXT[],
    user_id VARCHAR(100),

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Partition key for time-series data
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partition request_log by month for performance
-- (Partitioning setup - commented out for now, add when needed)
-- CREATE TABLE request_log_2025_10 PARTITION OF request_log
--     FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');

-- Indexes for request_log
CREATE INDEX idx_request_log_customer_timestamp ON request_log(customer_id, timestamp DESC);
CREATE INDEX idx_request_log_api_key_timestamp ON request_log(api_key_id, timestamp DESC);
CREATE INDEX idx_request_log_timestamp ON request_log(timestamp DESC);
CREATE INDEX idx_request_log_blocked ON request_log(customer_id) WHERE blocked = true;

-- ============================================================
-- 6. Helper Functions
-- ============================================================

-- Function to calculate overage for a customer in a given month
CREATE OR REPLACE FUNCTION calculate_monthly_overage(
    p_customer_id UUID,
    p_month_start TIMESTAMPTZ
) RETURNS TABLE (
    total_requests BIGINT,
    included_requests BIGINT,
    overage_requests BIGINT,
    overage_cost_cents INTEGER
) AS $$
DECLARE
    v_tier VARCHAR(20);
    v_mode VARCHAR(20);
    v_included BIGINT;
    v_total BIGINT;
    v_overage BIGINT;
    v_rate DECIMAL(10,4);
    v_cost INTEGER;
BEGIN
    -- Get customer tier and mode
    SELECT c.tier, c.deployment_mode INTO v_tier, v_mode
    FROM customers c WHERE c.customer_id = p_customer_id;

    -- Get included requests from pricing tier
    SELECT pt.included_requests, pt.overage_rate_per_1k INTO v_included, v_rate
    FROM pricing_tiers pt
    WHERE pt.tier = v_tier AND pt.deployment_mode = v_mode;

    -- SaaS mode only has overage
    IF v_mode = 'in-vpc' THEN
        RETURN QUERY SELECT 0::BIGINT, 0::BIGINT, 0::BIGINT, 0::INTEGER;
        RETURN;
    END IF;

    -- Calculate total requests for the month
    SELECT COALESCE(SUM(um.total_requests), 0) INTO v_total
    FROM usage_metrics um
    WHERE um.customer_id = p_customer_id
    AND um.period_start >= p_month_start
    AND um.period_start < p_month_start + INTERVAL '1 month'
    AND um.period_type = 'monthly';

    -- Calculate overage
    v_overage := GREATEST(0, v_total - COALESCE(v_included, 0));

    -- Calculate cost (overage_requests / 1000 * rate_per_1k)
    v_cost := FLOOR((v_overage::DECIMAL / 1000.0) * v_rate * 100);

    RETURN QUERY SELECT v_total, v_included, v_overage, v_cost;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- 7. Seed Data (existing clients from Option 2)
-- ============================================================

-- Insert existing customers
INSERT INTO customers (
    organization_name,
    organization_id,
    deployment_mode,
    tier,
    tenant_id,
    billing_email,
    contract_start_date,
    status,
    enabled,
    notes
) VALUES
('Healthcare Demo', 'healthcare', 'in-vpc', 'PLUS', 'healthcare_tenant', 'billing@healthcare-demo.com', '2025-01-01', 'active', true, 'Demo account for healthcare vertical'),
('E-commerce Demo', 'ecommerce', 'in-vpc', 'PLUS', 'ecommerce_tenant', 'billing@ecommerce-demo.com', '2025-01-01', 'active', true, 'Demo account for ecommerce vertical'),
('Legacy Client 1', 'client1', 'in-vpc', 'ENT', 'tenant_1', 'billing@client1.com', '2024-06-01', 'active', true, 'Legacy client from initial deployment'),
('Legacy Client 2', 'client2', 'in-vpc', 'ENT', 'tenant_2', 'billing@client2.com', '2024-06-01', 'active', true, 'Legacy client from initial deployment'),
('Load Testing', 'loadtest', 'in-vpc', 'PLUS', 'loadtest_tenant', 'noreply@getaxonflow.com', '2025-01-01', 'active', true, 'Internal load testing account')
ON CONFLICT (organization_id) DO NOTHING;

-- Insert API keys for existing customers (using existing license keys from Option 2)
INSERT INTO api_keys (
    customer_id,
    license_key,
    license_key_hash,
    key_name,
    key_type,
    expires_at,
    enabled
)
SELECT
    c.customer_id,
    k.license_key,
    encode(sha256(k.license_key::bytea), 'hex'),
    k.key_name,
    'production',
    '2035-10-25'::TIMESTAMPTZ,
    true
FROM customers c
CROSS JOIN LATERAL (
    SELECT * FROM (VALUES
        ('healthcare', 'AXON-PLUS-healthcare-20351025-4747f91a', 'Healthcare Production Key'),
        ('ecommerce', 'AXON-PLUS-ecommerce-20351025-a3702c14', 'E-commerce Production Key'),
        ('client1', 'AXON-ENT-client1-20351025-413f94a0', 'Client 1 Production Key'),
        ('client2', 'AXON-ENT-client2-20351025-90830d4c', 'Client 2 Production Key'),
        ('loadtest', 'AXON-PLUS-loadtest-20351025-820949e5', 'Load Testing Key')
    ) AS t(org_id, license_key, key_name)
    WHERE t.org_id = c.organization_id
) k
ON CONFLICT (license_key) DO NOTHING;

-- ============================================================
-- Comments for documentation
-- ============================================================
COMMENT ON TABLE pricing_tiers IS 'Defines pricing tiers for SaaS and In-VPC deployment modes';
COMMENT ON TABLE customers IS 'Customer organizations with contract and billing information';
COMMENT ON TABLE api_keys IS 'API keys (license keys) for customer authentication';
COMMENT ON TABLE usage_metrics IS 'Aggregated usage metrics for billing and monitoring';
COMMENT ON TABLE request_log IS 'Detailed request log for debugging and auditing (consider partitioning)';
COMMENT ON FUNCTION calculate_monthly_overage IS 'Calculates overage charges for a customer in a given month';
