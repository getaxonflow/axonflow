-- Migration 016: Service Identity & Permission System
-- Date: 2025-11-20
-- Description: Add service identity support to enable service-to-service authentication with role-based permissions
--
-- Purpose:
-- - Enable services (like trip planner) to authenticate with elevated permissions
-- - Separate service permissions from user permissions (security boundary)
-- - Industry-standard pattern (AWS IAM Roles, K8s ServiceAccounts, OAuth2 Client Credentials)
--
-- Architecture:
-- - Service identities define what permissions a service has
-- - License keys can optionally include service identity (service_name + permissions)
-- - Policy engine checks service permissions for MCP operations
--
-- Following: Principle 0 (Quality Over Velocity) and Principle 11 (No Shortcuts)

-- =============================================================================
-- Service Identities Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS service_identities (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(255), -- Multi-tenant isolation column for RLS
    tenant_id VARCHAR(255) NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    service_type VARCHAR(50) NOT NULL CHECK (service_type IN ('client-application', 'backend-service', 'integration')),
    description TEXT,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_tenant_service UNIQUE(tenant_id, service_name)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_service_identities_tenant
    ON service_identities(tenant_id);

CREATE INDEX IF NOT EXISTS idx_service_identities_active
    ON service_identities(active)
    WHERE active = true;

CREATE INDEX IF NOT EXISTS idx_service_identities_service_name
    ON service_identities(service_name);

-- Comments for documentation
COMMENT ON TABLE service_identities IS
    'Defines service identities with their associated permissions (AWS IAM Role pattern)';
COMMENT ON COLUMN service_identities.tenant_id IS
    'Tenant ID that owns this service (e.g., travel-eu, healthcare-eu)';
COMMENT ON COLUMN service_identities.service_name IS
    'Unique service name within tenant (e.g., trip-planner, booking-api)';
COMMENT ON COLUMN service_identities.service_type IS
    'Type of service: client-application, backend-service, or integration';
COMMENT ON COLUMN service_identities.permissions IS
    'Array of permission strings (e.g., mcp:amadeus:search_flights, mcp:slack:*)';
COMMENT ON COLUMN service_identities.active IS
    'Whether this service identity is active (allows quick revocation)';

-- =============================================================================
-- Extend License Keys Table (Create if not exists)
-- =============================================================================

-- Note: license_keys table may not exist yet (licenses currently validated from signed tokens)
-- This creates the table for future use when we want to track issued licenses
CREATE TABLE IF NOT EXISTS license_keys (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(255), -- Multi-tenant isolation column for RLS
    key_hash VARCHAR(512) NOT NULL UNIQUE,
    tenant_id VARCHAR(255) NOT NULL,
    tier VARCHAR(20) NOT NULL CHECK (tier IN ('PRO', 'ENT', 'PLUS')),
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Add service identity columns to license_keys (idempotent)
DO $$
BEGIN
    -- Add service_name column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'license_keys' AND column_name = 'service_name'
    ) THEN
        ALTER TABLE license_keys ADD COLUMN service_name VARCHAR(255);
    END IF;

    -- Add permissions column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'license_keys' AND column_name = 'permissions'
    ) THEN
        ALTER TABLE license_keys ADD COLUMN permissions TEXT[] DEFAULT '{}';
    END IF;

    -- Add service_type column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'license_keys' AND column_name = 'service_type'
    ) THEN
        ALTER TABLE license_keys ADD COLUMN service_type VARCHAR(50);
    END IF;
END $$;

-- Indexes for license_keys
CREATE INDEX IF NOT EXISTS idx_license_keys_tenant
    ON license_keys(tenant_id);

CREATE INDEX IF NOT EXISTS idx_license_keys_service
    ON license_keys(service_name)
    WHERE service_name IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_license_keys_active
    ON license_keys(active)
    WHERE active = true;

CREATE INDEX IF NOT EXISTS idx_license_keys_expires
    ON license_keys(expires_at);

-- Comments for license_keys
COMMENT ON TABLE license_keys IS
    'Tracks issued license keys (for management and revocation)';
COMMENT ON COLUMN license_keys.key_hash IS
    'SHA-256 hash of the license key for lookup without storing the key itself';
COMMENT ON COLUMN license_keys.service_name IS
    'Service name if this is a service license (NULL for regular org licenses)';
COMMENT ON COLUMN license_keys.permissions IS
    'Permissions embedded in service license (e.g., mcp:amadeus:*)';
COMMENT ON COLUMN license_keys.service_type IS
    'Type of service: client-application, backend-service, or integration';

-- =============================================================================
-- Example Service Identities (For Reference)
-- =============================================================================

-- Example: Trip Planner service with Amadeus permissions
INSERT INTO service_identities (
    tenant_id,
    service_name,
    service_type,
    description,
    permissions,
    active
) VALUES (
    'travel-eu',
    'trip-planner',
    'client-application',
    'Travel EU trip planning application with Amadeus flight/hotel search',
    ARRAY['mcp:amadeus:search_flights', 'mcp:amadeus:search_hotels', 'mcp:amadeus:lookup_airport'],
    true
) ON CONFLICT (tenant_id, service_name) DO NOTHING;

-- Example: Healthcare integration service
INSERT INTO service_identities (
    tenant_id,
    service_name,
    service_type,
    description,
    permissions,
    active
) VALUES (
    'healthcare-eu',
    'patient-portal',
    'backend-service',
    'Patient portal backend with access to Salesforce and Snowflake connectors',
    ARRAY['mcp:salesforce:*', 'mcp:snowflake:query'],
    true
) ON CONFLICT (tenant_id, service_name) DO NOTHING;

-- =============================================================================
-- Permission Format Documentation
-- =============================================================================

COMMENT ON COLUMN service_identities.permissions IS
    'Permission format: resource:connector:operation

    Examples:
    - mcp:amadeus:search_flights  (specific operation)
    - mcp:amadeus:*               (all Amadeus operations)
    - mcp:*                       (all MCP operations - admin only)

    Pattern matching:
    - Exact match: "mcp:amadeus:search_flights" matches exactly
    - Wildcard connector: "mcp:amadeus:*" matches all Amadeus operations
    - Global wildcard: "mcp:*" matches all MCP operations

    Security model:
    - End users have NO MCP permissions
    - Services have SPECIFIC MCP permissions
    - Agent validates service identity before allowing MCP queries
    - This prevents users from bypassing services to access connectors directly';

-- =============================================================================
-- Migration Tracking
-- =============================================================================

INSERT INTO schema_migrations (version, name, applied_at, success) VALUES
    ('021', 'service_identity_system', NOW(), true)
ON CONFLICT (version) DO NOTHING;

-- =============================================================================
-- Migration Complete
-- =============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Migration 021 completed successfully';
    RAISE NOTICE 'Created service_identities table';
    RAISE NOTICE 'Extended license_keys table with service identity fields';
    RAISE NOTICE 'Inserted 2 example service identities (travel-eu, healthcare-eu)';
    RAISE NOTICE 'Service identity system ready for use';
END $$;
