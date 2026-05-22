-- Rollback for migration 097: restore register_tenant() to its pre-v9 body
-- (no client_id write). Mirrors the original definition in migration 062.

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
