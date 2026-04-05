-- Migration 062: Tenants table for org→tenant mapping
-- Date: 2026-04-04
-- Context: Issue #1492 — Unified identity model
--
-- Maps tenant_id (from Basic auth clientId) to org_id (from license).
-- Auto-populated on first authenticated request via register_tenant().
-- Enables multi-tenant: same org, different tenants (prod, staging, dev).

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    org_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    environment VARCHAR(50),  -- prod, staging, dev, local
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- FK to organizations table (migration 002)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_tenants_org'
        AND table_name = 'tenants'
    ) THEN
        -- Only add FK if organizations table exists (it may not in community-only deployments)
        IF EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_name = 'organizations'
        ) THEN
            ALTER TABLE tenants
            ADD CONSTRAINT fk_tenants_org
            FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE;
        END IF;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_tenants_org_id ON tenants(org_id);

-- Auto-register tenant on first request (upsert)
CREATE OR REPLACE FUNCTION register_tenant(
    p_tenant_id VARCHAR(255),
    p_org_id VARCHAR(255),
    p_name VARCHAR(255) DEFAULT NULL
) RETURNS VOID AS $$
BEGIN
    INSERT INTO tenants (tenant_id, org_id, name)
    VALUES (p_tenant_id, p_org_id, COALESCE(p_name, p_tenant_id))
    ON CONFLICT (tenant_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- Auto-register org for self-hosted users who don't seed the DB manually.
-- Uses organizations table from migration 002.
-- Tier and max_nodes come from the validated license so the org record
-- reflects the actual entitlement, not hardcoded defaults.
CREATE OR REPLACE FUNCTION register_org(
    p_org_id VARCHAR(255),
    p_name VARCHAR(255) DEFAULT NULL,
    p_tier VARCHAR(50) DEFAULT 'Community',
    p_max_nodes INTEGER DEFAULT 2
) RETURNS VOID AS $$
BEGIN
    -- Only if organizations table exists
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'organizations'
    ) THEN
        INSERT INTO organizations (org_id, name, tier, max_nodes, license_key)
        VALUES (p_org_id, COALESCE(p_name, p_org_id), p_tier, p_max_nodes, '')
        ON CONFLICT (org_id) DO UPDATE SET
            tier = EXCLUDED.tier,
            max_nodes = EXCLUDED.max_nodes,
            updated_at = CURRENT_TIMESTAMP
        WHERE organizations.tier != EXCLUDED.tier
           OR organizations.max_nodes != EXCLUDED.max_nodes;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Update trigger for tenants
DROP TRIGGER IF EXISTS update_tenants_updated_at ON tenants;
CREATE TRIGGER update_tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Success
DO $$
BEGIN
    RAISE NOTICE 'Migration 060: Created tenants table with auto-register functions';
END $$;
