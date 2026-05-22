-- Rollback for migration 104: SECURITY DEFINER auth helpers
--
-- Restores register_org + register_tenant + portal_default_tenant_id to
-- their pre-mig-104 (non-SECURITY-DEFINER) bodies from migrations 062 + 097
-- + 065 respectively. Drops the two NEW functions (portal_auth_lookup_org +
-- portal_check_sso_availability) entirely.
--
-- WARNING: downgrading these functions OFF SECURITY DEFINER while FORCE RLS
-- on organizations + tenants (migration 103) remains active will silently
-- re-break HandleLogin + HandleCheckSSOAvailability + registerTenantAndOrg
-- once AXONFLOW_DB_USE_APP_ROLE=true is set. ONLY run this rollback in
-- coordination with rolling 103 back too.

BEGIN;

-- ============================================================================
-- Drop the two NEW pre-auth helpers
-- ============================================================================
DROP FUNCTION IF EXISTS portal_auth_lookup_org(VARCHAR);
DROP FUNCTION IF EXISTS portal_check_sso_availability(VARCHAR);

-- ============================================================================
-- Restore portal_default_tenant_id to its pre-104 (non-SECURITY-DEFINER) body
-- from migration 065
-- ============================================================================
CREATE OR REPLACE FUNCTION portal_default_tenant_id(p_org_id VARCHAR(255))
RETURNS VARCHAR(255) AS $$
DECLARE
    result VARCHAR(255);
BEGIN
    SELECT tenant_id INTO result
    FROM tenants
    WHERE org_id = p_org_id AND tenant_id = p_org_id
    LIMIT 1;

    IF result IS NOT NULL THEN
        RETURN result;
    END IF;

    SELECT tenant_id INTO result
    FROM tenants
    WHERE org_id = p_org_id
    ORDER BY created_at ASC
    LIMIT 1;

    IF result IS NULL THEN
        result := p_org_id;
    END IF;

    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Restore register_org to its pre-104 (non-SECURITY-DEFINER) body from
-- migration 062
-- ============================================================================
CREATE OR REPLACE FUNCTION register_org(
    p_org_id VARCHAR(255),
    p_name VARCHAR(255) DEFAULT NULL,
    p_tier VARCHAR(50) DEFAULT 'Community',
    p_max_nodes INTEGER DEFAULT 2
) RETURNS VOID AS $$
BEGIN
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

-- ============================================================================
-- Restore register_tenant to its pre-104 body (the mig-097 client_id body,
-- without SECURITY DEFINER)
-- ============================================================================
CREATE OR REPLACE FUNCTION register_tenant(
    p_tenant_id VARCHAR(255),
    p_org_id VARCHAR(255),
    p_name VARCHAR(255) DEFAULT NULL
) RETURNS VOID AS $$
BEGIN
    INSERT INTO tenants (tenant_id, client_id, org_id, name)
    VALUES (p_tenant_id, p_tenant_id, p_org_id, COALESCE(p_name, p_tenant_id))
    ON CONFLICT (tenant_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

COMMIT;
