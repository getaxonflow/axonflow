-- Migration 002: Customer Portal
-- Date: 2025-10-28
-- Description: Tables for customer portal, SSO/SAML, API keys, and observability

-- =============================================================================
-- Customer Organizations
-- =============================================================================

CREATE TABLE IF NOT EXISTS organizations (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    license_key VARCHAR(512) NOT NULL,
    tier VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'ACTIVE',
    max_nodes INTEGER NOT NULL DEFAULT 10,
    expires_at TIMESTAMP,
    contact_email VARCHAR(255),
    contact_phone VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_organizations_org_id ON organizations(org_id);
CREATE INDEX IF NOT EXISTS idx_organizations_license_key ON organizations(license_key);
CREATE INDEX IF NOT EXISTS idx_organizations_status ON organizations(status);

COMMENT ON TABLE organizations IS 'Customer organizations with license information';
COMMENT ON COLUMN organizations.org_id IS 'Unique organization identifier';
COMMENT ON COLUMN organizations.license_key IS 'License key for this organization';
COMMENT ON COLUMN organizations.tier IS 'Subscription tier (DEVELOPER, PROFESSIONAL, ENTERPRISE)';
COMMENT ON COLUMN organizations.status IS 'Organization status (ACTIVE, SUSPENDED, CANCELLED)';

-- =============================================================================
-- SAML Configurations
-- =============================================================================

CREATE TABLE IF NOT EXISTS saml_configurations (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(255) UNIQUE NOT NULL,
    provider VARCHAR(50) NOT NULL,
    idp_metadata_url TEXT NOT NULL,
    idp_entity_id VARCHAR(255) NOT NULL,
    idp_sso_url TEXT NOT NULL,
    idp_certificate TEXT NOT NULL,
    sp_entity_id VARCHAR(255) NOT NULL,
    sp_acs_url TEXT NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_saml_org_id ON saml_configurations(org_id);
CREATE INDEX IF NOT EXISTS idx_saml_provider ON saml_configurations(provider);
CREATE INDEX IF NOT EXISTS idx_saml_enabled ON saml_configurations(enabled);

COMMENT ON TABLE saml_configurations IS 'SAML SSO configurations per organization';
COMMENT ON COLUMN saml_configurations.provider IS 'SSO provider (okta, azure, auth0)';
COMMENT ON COLUMN saml_configurations.idp_metadata_url IS 'Identity Provider metadata URL';
COMMENT ON COLUMN saml_configurations.enabled IS 'Whether this SAML config is active';

-- =============================================================================
-- API Keys
-- =============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(255) NOT NULL,
    key_hash VARCHAR(512) NOT NULL UNIQUE,
    key_prefix VARCHAR(20) NOT NULL,
    name VARCHAR(255) NOT NULL,
    scopes JSONB DEFAULT '[]',
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP
);

-- Create indexes only if the columns exist (handles legacy api_keys table)
DO $$
BEGIN
    -- Check if this is the new api_keys schema (has key_hash column)
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'api_keys' AND column_name = 'key_hash'
    ) THEN
        -- New schema - create all indexes
        CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id);
        CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
        CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
        CREATE INDEX IF NOT EXISTS idx_api_keys_revoked ON api_keys(revoked_at) WHERE revoked_at IS NULL;

        COMMENT ON TABLE api_keys IS 'API keys for programmatic access to AxonFlow';
        COMMENT ON COLUMN api_keys.key_hash IS 'SHA-256 hash of the API key';
        COMMENT ON COLUMN api_keys.key_prefix IS 'Prefix for display (e.g., axon_1234...)';
        COMMENT ON COLUMN api_keys.scopes IS 'JSON array of permission scopes';
        COMMENT ON COLUMN api_keys.last_used_at IS 'Last time this key was used';
        COMMENT ON COLUMN api_keys.expires_at IS 'Expiration timestamp (NULL = never expires)';
        COMMENT ON COLUMN api_keys.revoked_at IS 'When this key was revoked (NULL = active)';
    ELSE
        -- Legacy schema - skip indexes (migration 010 will create customer_portal_api_keys instead)
        RAISE NOTICE 'Legacy api_keys table detected - skipping indexes (see migration 010)';
    END IF;
END $$;

-- =============================================================================
-- User Sessions
-- =============================================================================

CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    org_id VARCHAR(255) NOT NULL,
    user_email VARCHAR(255) NOT NULL,
    user_name VARCHAR(255),
    user_attributes JSONB,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sessions_id ON user_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_org ON user_sessions(org_id);
CREATE INDEX IF NOT EXISTS idx_sessions_email ON user_sessions(user_email);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);

COMMENT ON TABLE user_sessions IS 'Active user sessions from SSO/SAML login';
COMMENT ON COLUMN user_sessions.session_id IS 'Unique session identifier (UUID)';
COMMENT ON COLUMN user_sessions.user_attributes IS 'Additional SAML attributes from IdP';
COMMENT ON COLUMN user_sessions.expires_at IS 'Session expiration timestamp';
COMMENT ON COLUMN user_sessions.last_activity_at IS 'Last activity timestamp for this session';

-- =============================================================================
-- Grafana Organizations
-- =============================================================================

CREATE TABLE IF NOT EXISTS grafana_organizations (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(255) UNIQUE NOT NULL,
    grafana_org_id BIGINT NOT NULL,
    grafana_org_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_grafana_orgs_org_id ON grafana_organizations(org_id);
CREATE INDEX IF NOT EXISTS idx_grafana_orgs_grafana_id ON grafana_organizations(grafana_org_id);

COMMENT ON TABLE grafana_organizations IS 'Mapping between AxonFlow orgs and Grafana organizations';
COMMENT ON COLUMN grafana_organizations.grafana_org_id IS 'Grafana organization ID';
COMMENT ON COLUMN grafana_organizations.grafana_org_name IS 'Grafana organization name';

-- =============================================================================
-- Session Cleanup Function
-- =============================================================================

-- Function to automatically delete expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM user_sessions WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_sessions IS 'Deletes expired user sessions';

-- =============================================================================
-- Update Triggers
-- =============================================================================

-- Trigger to update updated_at timestamp on organizations
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_organizations_updated_at ON organizations;
CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_saml_configurations_updated_at ON saml_configurations;
CREATE TRIGGER update_saml_configurations_updated_at
    BEFORE UPDATE ON saml_configurations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Foreign Key Constraints (Added separately for idempotency)
-- =============================================================================

-- Ensure org_id column exists in all tables before adding FK constraints
-- This is needed because CREATE TABLE IF NOT EXISTS skips existing tables
-- and doesn't add new columns to old table versions

-- Add org_id to saml_configurations if not exists
ALTER TABLE saml_configurations
ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);

-- Add FK for saml_configurations if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'saml_configurations_org_id_fkey'
        AND table_name = 'saml_configurations'
    ) THEN
        ALTER TABLE saml_configurations
        ADD CONSTRAINT saml_configurations_org_id_fkey
        FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE;
    END IF;
END $$;

-- Add org_id to api_keys if not exists
ALTER TABLE api_keys
ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);

-- Add FK for api_keys if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'api_keys_org_id_fkey'
        AND table_name = 'api_keys'
    ) THEN
        ALTER TABLE api_keys
        ADD CONSTRAINT api_keys_org_id_fkey
        FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE;
    END IF;
END $$;

-- Add org_id to user_sessions if not exists
ALTER TABLE user_sessions
ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);

-- Add FK for user_sessions if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'user_sessions_org_id_fkey'
        AND table_name = 'user_sessions'
    ) THEN
        ALTER TABLE user_sessions
        ADD CONSTRAINT user_sessions_org_id_fkey
        FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE;
    END IF;
END $$;

-- Add org_id to grafana_organizations if not exists
ALTER TABLE grafana_organizations
ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);

-- Add FK for grafana_organizations if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'grafana_organizations_org_id_fkey'
        AND table_name = 'grafana_organizations'
    ) THEN
        ALTER TABLE grafana_organizations
        ADD CONSTRAINT grafana_organizations_org_id_fkey
        FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE;
    END IF;
END $$;

-- =============================================================================
-- Migration Complete
-- =============================================================================
-- NOTE: Test data seeding is handled by the seed-test-data.yml workflow, not migrations.
-- This keeps migrations focused on schema changes only and prevents test data
-- from accidentally being created in production databases.

-- Display success message
DO $$
BEGIN
    RAISE NOTICE 'Migration 006 completed successfully';
    RAISE NOTICE 'Tables created: organizations, saml_configurations, api_keys, user_sessions, grafana_organizations';
    RAISE NOTICE 'Indexes created: 15 indexes for performance optimization';
    RAISE NOTICE 'Triggers created: update_updated_at triggers';
END $$;
