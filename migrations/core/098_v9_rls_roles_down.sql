-- Migration 098 DOWN: drop axonflow_app_role + axonflow_platform_admin
-- Context: reverses 098_v9_rls_roles.sql
--
-- WARNING: destructive. Any deployment that has flipped
--          AXONFLOW_DB_USE_APP_ROLE=true is currently connected as
--          axonflow_app_role. Dropping the role will sever those connections.
--          Operators must flip the env back to false and redeploy BEFORE
--          applying this down migration.

BEGIN;

-- Revoke default privileges first (REVOKE-DEFAULT is symmetric to GRANT-DEFAULT
-- and must run from the same role context that granted them).
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM axonflow_app_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE USAGE, SELECT ON SEQUENCES FROM axonflow_app_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM axonflow_platform_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE USAGE, SELECT ON SEQUENCES FROM axonflow_platform_admin;

-- Revoke existing-table privileges.
REVOKE SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM axonflow_app_role;
REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public FROM axonflow_app_role;
REVOKE SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM axonflow_platform_admin;
REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public FROM axonflow_platform_admin;

REVOKE USAGE ON SCHEMA public FROM axonflow_app_role;
REVOKE USAGE ON SCHEMA public FROM axonflow_platform_admin;

-- Drop the roles. DROP ROLE fails if any objects are still owned by the role,
-- but since these roles never OWN anything (the table owner is the RDS master),
-- this should succeed cleanly.
DROP ROLE IF EXISTS axonflow_app_role;
DROP ROLE IF EXISTS axonflow_platform_admin;

COMMIT;
