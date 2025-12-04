-- Rollback migration 023: Custom Roles

DROP POLICY IF EXISTS role_assignments_tenant_isolation ON role_assignments;
DROP POLICY IF EXISTS custom_roles_tenant_isolation ON custom_roles;
DROP TABLE IF EXISTS role_assignments;
DROP TABLE IF EXISTS custom_roles;
