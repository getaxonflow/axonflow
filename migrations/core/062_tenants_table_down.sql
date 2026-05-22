-- Rollback Migration 062: Remove tenants table and auto-register functions

DROP TRIGGER IF EXISTS update_tenants_updated_at ON tenants;
DROP TABLE IF EXISTS tenants CASCADE;
DROP FUNCTION IF EXISTS register_tenant(VARCHAR, VARCHAR, VARCHAR);
DROP FUNCTION IF EXISTS register_org(VARCHAR, VARCHAR, VARCHAR);
