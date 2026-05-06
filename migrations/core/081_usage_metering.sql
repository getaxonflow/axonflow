-- Migration 081: Usage Metering System
--
-- Purpose: Track API calls, tokens, LLM costs for usage-based billing
-- and so the agent's UsageRecorder (recorder_enterprise.go) has its
-- target tables present in every deployment mode that runs the
-- enterprise build, including community-saas — without this promotion
-- the enterprise binary's per-request RecordAPICall() goroutine logs
-- 'relation "usage_events" does not exist' on every proxied request
-- (community-saas only loads migrations/core/, not enterprise/).
--
-- Promoted from migrations/enterprise/104_usage_metering.sql per #1884.
-- The original 104 was tracked in schema_migrations on existing SaaS
-- prod deployments, so this is filed under a fresh core/081 number.
-- All CREATE TABLE / CREATE INDEX statements use IF NOT EXISTS so
-- replaying on a stack that already has migration 104 applied is a
-- no-op; the CREATE OR REPLACE FUNCTION bodies are byte-identical to
-- 104 so the function definitions don't drift.
--
-- Original date: 2025-11-20 (preserved for git-blame continuity)

-- =====================================================
-- 1. Raw Usage Events Table (time-series data)
-- =====================================================

CREATE TABLE IF NOT EXISTS usage_events (
    id BIGSERIAL PRIMARY KEY,
    org_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255),  -- Optional: track usage by client within org
    event_type VARCHAR(50) NOT NULL,  -- 'api_call', 'llm_request', 'policy_eval', etc.

    -- Request/Response metadata
    instance_id VARCHAR(255),  -- Which agent/orchestrator processed this
    instance_type VARCHAR(50),  -- 'agent' or 'orchestrator'
    http_method VARCHAR(10),
    http_path TEXT,
    http_status_code INTEGER,

    -- LLM-specific metrics
    llm_provider VARCHAR(50),  -- 'openai', 'anthropic', 'cohere', etc.
    llm_model VARCHAR(100),  -- 'gpt-4', 'claude-3-sonnet', etc.
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,

    -- Cost calculation (in USD cents to avoid floating point issues)
    estimated_cost_cents INTEGER DEFAULT 0,

    -- Performance metrics
    latency_ms INTEGER,

    -- Policy evaluation
    policies_evaluated INTEGER DEFAULT 0,
    policy_violations INTEGER DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Add org_id column if not exists (for existing tables)
ALTER TABLE usage_events
ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);

-- Add FK constraint conditionally
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_usage_org'
        AND table_name = 'usage_events'
    ) THEN
        ALTER TABLE usage_events
        ADD CONSTRAINT fk_usage_org FOREIGN KEY (org_id)
        REFERENCES organizations(org_id) ON DELETE CASCADE;
    END IF;
END $$;

-- Indexes for fast time-series queries
CREATE INDEX IF NOT EXISTS idx_usage_events_org_created
    ON usage_events(org_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_usage_events_client_created
    ON usage_events(client_id, created_at DESC)
    WHERE client_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_usage_events_type_created
    ON usage_events(event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_usage_events_created
    ON usage_events(created_at DESC);

-- Partition by month for better performance (PostgreSQL 10+)
-- Note: Initial table is not partitioned; can be converted later if needed

-- =====================================================
-- 2. Hourly Usage Aggregates
-- =====================================================

CREATE TABLE IF NOT EXISTS usage_hourly (
    id BIGSERIAL PRIMARY KEY,
    org_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255),
    event_type VARCHAR(50) NOT NULL,
    hour_bucket TIMESTAMP WITH TIME ZONE NOT NULL,  -- Truncated to hour

    -- Aggregated metrics
    event_count INTEGER NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    total_cost_cents BIGINT NOT NULL DEFAULT 0,

    -- Performance aggregates
    avg_latency_ms INTEGER,
    p50_latency_ms INTEGER,
    p95_latency_ms INTEGER,
    p99_latency_ms INTEGER,

    -- Policy metrics
    total_policies_evaluated BIGINT NOT NULL DEFAULT 0,
    total_policy_violations BIGINT NOT NULL DEFAULT 0,

    -- Success/Error breakdown
    success_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Add org_id column if not exists (for existing tables)
ALTER TABLE usage_hourly
ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);

-- Add FK constraint conditionally
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_usage_hourly_org'
        AND table_name = 'usage_hourly'
    ) THEN
        ALTER TABLE usage_hourly
        ADD CONSTRAINT fk_usage_hourly_org FOREIGN KEY (org_id)
        REFERENCES organizations(org_id) ON DELETE CASCADE;
    END IF;
END $$;

-- Unique index to enforce one row per org/client/event_type/hour
CREATE UNIQUE INDEX IF NOT EXISTS idx_usage_hourly_unique
    ON usage_hourly(org_id, COALESCE(client_id, ''), event_type, hour_bucket);

CREATE INDEX IF NOT EXISTS idx_usage_hourly_org_hour
    ON usage_hourly(org_id, hour_bucket DESC);

CREATE INDEX IF NOT EXISTS idx_usage_hourly_client_hour
    ON usage_hourly(client_id, hour_bucket DESC)
    WHERE client_id IS NOT NULL;

-- =====================================================
-- 3. Daily Usage Aggregates
-- =====================================================

CREATE TABLE IF NOT EXISTS usage_daily (
    id BIGSERIAL PRIMARY KEY,
    org_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255),
    event_type VARCHAR(50) NOT NULL,
    day_bucket DATE NOT NULL,

    -- Aggregated metrics
    event_count INTEGER NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    total_cost_cents BIGINT NOT NULL DEFAULT 0,

    -- Performance aggregates
    avg_latency_ms INTEGER,

    -- Policy metrics
    total_policies_evaluated BIGINT NOT NULL DEFAULT 0,
    total_policy_violations BIGINT NOT NULL DEFAULT 0,

    -- Success/Error breakdown
    success_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Add org_id column if not exists (for existing tables)
ALTER TABLE usage_daily
ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);

-- Add FK constraint conditionally
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_usage_daily_org'
        AND table_name = 'usage_daily'
    ) THEN
        ALTER TABLE usage_daily
        ADD CONSTRAINT fk_usage_daily_org FOREIGN KEY (org_id)
        REFERENCES organizations(org_id) ON DELETE CASCADE;
    END IF;
END $$;

-- Unique index to enforce one row per org/client/event_type/day
CREATE UNIQUE INDEX IF NOT EXISTS idx_usage_daily_unique
    ON usage_daily(org_id, COALESCE(client_id, ''), event_type, day_bucket);

CREATE INDEX IF NOT EXISTS idx_usage_daily_org_day
    ON usage_daily(org_id, day_bucket DESC);

CREATE INDEX IF NOT EXISTS idx_usage_daily_client_day
    ON usage_daily(client_id, day_bucket DESC)
    WHERE client_id IS NOT NULL;

-- =====================================================
-- 4. Monthly Usage Aggregates (for billing)
-- =====================================================

CREATE TABLE IF NOT EXISTS usage_monthly (
    id BIGSERIAL PRIMARY KEY,
    org_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255),
    month_bucket DATE NOT NULL,  -- First day of month

    -- Aggregated metrics (all event types combined)
    total_api_calls BIGINT NOT NULL DEFAULT 0,
    total_llm_requests BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    total_cost_cents BIGINT NOT NULL DEFAULT 0,

    -- Policy metrics
    total_policies_evaluated BIGINT NOT NULL DEFAULT 0,
    total_policy_violations BIGINT NOT NULL DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Add org_id column if not exists (for existing tables)
ALTER TABLE usage_monthly
ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);

-- Add FK constraint conditionally
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_usage_monthly_org'
        AND table_name = 'usage_monthly'
    ) THEN
        ALTER TABLE usage_monthly
        ADD CONSTRAINT fk_usage_monthly_org FOREIGN KEY (org_id)
        REFERENCES organizations(org_id) ON DELETE CASCADE;
    END IF;
END $$;

-- Unique index to enforce one row per org/client/month
CREATE UNIQUE INDEX IF NOT EXISTS idx_usage_monthly_unique
    ON usage_monthly(org_id, COALESCE(client_id, ''), month_bucket);

CREATE INDEX IF NOT EXISTS idx_usage_monthly_org_month
    ON usage_monthly(org_id, month_bucket DESC);

-- =====================================================
-- 5. Data Retention Policy
-- =====================================================

-- Delete raw events older than 90 days (keep aggregates)
-- Run this as a cron job or scheduled task

CREATE OR REPLACE FUNCTION cleanup_old_usage_events()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM usage_events
    WHERE created_at < NOW() - INTERVAL '90 days';

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- 6. Helper Functions
-- =====================================================

-- Function to aggregate hourly data
CREATE OR REPLACE FUNCTION aggregate_usage_hourly(
    p_start_time TIMESTAMP WITH TIME ZONE,
    p_end_time TIMESTAMP WITH TIME ZONE
)
RETURNS INTEGER AS $$
DECLARE
    aggregated_count INTEGER := 0;
BEGIN
    INSERT INTO usage_hourly (
        org_id, client_id, event_type, hour_bucket,
        event_count, total_tokens, prompt_tokens, completion_tokens,
        total_cost_cents, avg_latency_ms,
        total_policies_evaluated, total_policy_violations,
        success_count, error_count
    )
    SELECT
        org_id,
        client_id,
        event_type,
        DATE_TRUNC('hour', created_at) as hour_bucket,
        COUNT(*) as event_count,
        SUM(total_tokens) as total_tokens,
        SUM(prompt_tokens) as prompt_tokens,
        SUM(completion_tokens) as completion_tokens,
        SUM(estimated_cost_cents) as total_cost_cents,
        AVG(latency_ms)::INTEGER as avg_latency_ms,
        SUM(policies_evaluated) as total_policies_evaluated,
        SUM(policy_violations) as total_policy_violations,
        SUM(CASE WHEN http_status_code < 400 THEN 1 ELSE 0 END) as success_count,
        SUM(CASE WHEN http_status_code >= 400 THEN 1 ELSE 0 END) as error_count
    FROM usage_events
    WHERE created_at >= p_start_time
      AND created_at < p_end_time
    GROUP BY org_id, client_id, event_type, DATE_TRUNC('hour', created_at)
    ON CONFLICT (org_id, COALESCE(client_id, ''), event_type, hour_bucket)
    DO UPDATE SET
        event_count = usage_hourly.event_count + EXCLUDED.event_count,
        total_tokens = usage_hourly.total_tokens + EXCLUDED.total_tokens,
        prompt_tokens = usage_hourly.prompt_tokens + EXCLUDED.prompt_tokens,
        completion_tokens = usage_hourly.completion_tokens + EXCLUDED.completion_tokens,
        total_cost_cents = usage_hourly.total_cost_cents + EXCLUDED.total_cost_cents,
        updated_at = NOW();

    GET DIAGNOSTICS aggregated_count = ROW_COUNT;
    RETURN aggregated_count;
END;
$$ LANGUAGE plpgsql;

-- Function to aggregate daily data
CREATE OR REPLACE FUNCTION aggregate_usage_daily(
    p_start_date DATE,
    p_end_date DATE
)
RETURNS INTEGER AS $$
DECLARE
    aggregated_count INTEGER := 0;
BEGIN
    INSERT INTO usage_daily (
        org_id, client_id, event_type, day_bucket,
        event_count, total_tokens, prompt_tokens, completion_tokens,
        total_cost_cents, avg_latency_ms,
        total_policies_evaluated, total_policy_violations,
        success_count, error_count
    )
    SELECT
        org_id,
        client_id,
        event_type,
        hour_bucket::DATE as day_bucket,
        SUM(event_count) as event_count,
        SUM(total_tokens) as total_tokens,
        SUM(prompt_tokens) as prompt_tokens,
        SUM(completion_tokens) as completion_tokens,
        SUM(total_cost_cents) as total_cost_cents,
        AVG(avg_latency_ms)::INTEGER as avg_latency_ms,
        SUM(total_policies_evaluated) as total_policies_evaluated,
        SUM(total_policy_violations) as total_policy_violations,
        SUM(success_count) as success_count,
        SUM(error_count) as error_count
    FROM usage_hourly
    WHERE hour_bucket::DATE >= p_start_date
      AND hour_bucket::DATE < p_end_date
    GROUP BY org_id, client_id, event_type, hour_bucket::DATE
    ON CONFLICT (org_id, COALESCE(client_id, ''), event_type, day_bucket)
    DO UPDATE SET
        event_count = usage_daily.event_count + EXCLUDED.event_count,
        total_tokens = usage_daily.total_tokens + EXCLUDED.total_tokens,
        prompt_tokens = usage_daily.prompt_tokens + EXCLUDED.prompt_tokens,
        completion_tokens = usage_daily.completion_tokens + EXCLUDED.completion_tokens,
        total_cost_cents = usage_daily.total_cost_cents + EXCLUDED.total_cost_cents,
        updated_at = NOW();

    GET DIAGNOSTICS aggregated_count = ROW_COUNT;
    RETURN aggregated_count;
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- 7. Row-Level Security (mirrors migration 018's per-table loop)
-- =====================================================
--
-- Migration 018 (RLS bootstrap) runs BEFORE this one in version order
-- and explicitly skips tables that don't exist yet — so on any deployment
-- where 018 ran before 081, the usage_* tables would not get RLS even
-- after 081 created them. This block re-applies the same enable-RLS +
-- create-tenant-isolation-policies pattern for the 4 tables this
-- migration creates. Idempotent via DROP POLICY IF EXISTS / re-CREATE.
-- get_current_org_id() is defined by 018 itself, so it is guaranteed
-- to exist by the time 081 runs.
DO $$
DECLARE
    usage_tables text[] := ARRAY['usage_events', 'usage_hourly', 'usage_daily', 'usage_monthly'];
    tbl_name text;
BEGIN
    FOREACH tbl_name IN ARRAY usage_tables
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl_name);

        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_select ON %I', tbl_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_insert ON %I', tbl_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_update ON %I', tbl_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_delete ON %I', tbl_name);

        EXECUTE format('CREATE POLICY tenant_isolation_select ON %I FOR SELECT USING (org_id = get_current_org_id())', tbl_name);
        EXECUTE format('CREATE POLICY tenant_isolation_insert ON %I FOR INSERT WITH CHECK (org_id = get_current_org_id())', tbl_name);
        EXECUTE format('CREATE POLICY tenant_isolation_update ON %I FOR UPDATE USING (org_id = get_current_org_id())', tbl_name);
        EXECUTE format('CREATE POLICY tenant_isolation_delete ON %I FOR DELETE USING (org_id = get_current_org_id())', tbl_name);

        RAISE NOTICE 'Migration 081: enabled RLS on %', tbl_name;
    END LOOP;
END $$;

-- NOTE: Test data should NOT be in migrations. Use the seed-test-data workflow instead.
