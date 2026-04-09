-- Migration 068: Community-SaaS tenant registration and daily usage tracking
-- Date: 2026-04-09
-- Context: Issue #1500 — Community SaaS evaluation server (try.getaxonflow.com)
--
-- Provides:
--   community_saas_registrations — credential store for self-registered tenants
--   community_saas_daily_usage   — atomic daily counter for daily rate limiting
--   increment_csaas_daily()      — upserts daily counter, returns new count
--
-- Depends on: 062_tenants_table (register_tenant, register_org functions)

-- Credential store for self-registered community-saas tenants.
-- Each row represents one registration with a bcrypt-hashed secret.
-- tenant_id is prefixed with "cs_" to distinguish from licensed tenants.
CREATE TABLE IF NOT EXISTS community_saas_registrations (
    tenant_id      VARCHAR(255) PRIMARY KEY,
    secret_hash    VARCHAR(255) NOT NULL,
    secret_prefix  VARCHAR(10)  NOT NULL,
    org_id         VARCHAR(255) NOT NULL DEFAULT 'community-saas',
    label          VARCHAR(255),
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW() + INTERVAL '30 days',
    last_seen_at   TIMESTAMP WITH TIME ZONE,
    request_count  BIGINT NOT NULL DEFAULT 0,
    disabled_at    TIMESTAMP WITH TIME ZONE
);

-- Index for cleanup queries (expired tenant purge)
CREATE INDEX IF NOT EXISTS idx_csaas_reg_expires
    ON community_saas_registrations(expires_at);

-- Index for org-level queries (all tenants in community-saas org)
CREATE INDEX IF NOT EXISTS idx_csaas_reg_org
    ON community_saas_registrations(org_id);

-- Daily request counter for per-tenant daily rate limiting.
-- One row per (tenant, UTC date). Atomic increment via upsert.
-- Cleanup: DELETE FROM community_saas_daily_usage WHERE day < CURRENT_DATE - 30
-- (run periodically via cron job or scheduled task)
CREATE TABLE IF NOT EXISTS community_saas_daily_usage (
    tenant_id  VARCHAR(255) NOT NULL,
    day        DATE         NOT NULL,
    req_count  INTEGER      NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, day)
);

-- Index for cleanup queries (old daily usage rows)
CREATE INDEX IF NOT EXISTS idx_csaas_daily_day
    ON community_saas_daily_usage(day);

-- Increments the daily request counter for a tenant.
-- Creates the row if it doesn't exist (first request of the day).
-- Returns the new count after increment.
CREATE OR REPLACE FUNCTION increment_csaas_daily(
    p_tenant_id VARCHAR(255),
    p_day       DATE
) RETURNS INTEGER AS $$
DECLARE
    new_count INTEGER;
BEGIN
    INSERT INTO community_saas_daily_usage (tenant_id, day, req_count)
    VALUES (p_tenant_id, p_day, 1)
    ON CONFLICT (tenant_id, day) DO UPDATE
        SET req_count = community_saas_daily_usage.req_count + 1
    RETURNING req_count INTO new_count;
    RETURN new_count;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    RAISE NOTICE 'Migration 068: community_saas_registrations + community_saas_daily_usage tables created';
END $$;
