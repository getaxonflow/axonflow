-- Migration 098: v9 RLS roles (axonflow_app_role + axonflow_platform_admin)
-- Date: 2026-05-20
--
-- Creates the two Postgres roles that make FORCE ROW LEVEL SECURITY meaningful:
--
--   1. axonflow_app_role — used by normal request traffic (agent, orchestrator,
--      portal) when AXONFLOW_DB_USE_APP_ROLE=true. NOT a superuser, NOT BYPASSRLS.
--      Subject to every RLS policy. Requires SET LOCAL app.current_org_id on
--      every transaction.
--
--   2. axonflow_platform_admin — used by legitimate cross-org workers (sweep,
--      aggregators, mirror, bridge, csaas-mirror, scripts). Has BYPASSRLS so
--      these workers can iterate across orgs without playing RLS gymnastics.
--
-- Both roles are LOGIN-capable. Passwords are NOT set here — they're managed by
-- the deployment scripts that read from AWS Secrets Manager. The migration
-- creates the role shells; production rotates passwords post-deployment.
--
-- Idempotent: re-runs on existing installs are no-ops (DO blocks guard CREATE).
--
-- Grants: only on schemas that already exist. The grants target tables the
-- agent + orchestrator + portal touch today. New schemas added in future
-- migrations need their own grants in the migration that creates them.

BEGIN;

-- ============================================================================
-- Role: axonflow_app_role (LOGIN, no BYPASSRLS)
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        CREATE ROLE axonflow_app_role LOGIN;
        RAISE NOTICE 'Created role: axonflow_app_role';
    ELSE
        RAISE NOTICE 'Role axonflow_app_role already exists (idempotent skip)';
    END IF;
END
$$;

-- Explicitly deny BYPASSRLS on the app role (defensive — CREATE ROLE default
-- is no BYPASSRLS, but make the intent explicit so future ALTERs are obvious).
ALTER ROLE axonflow_app_role NOBYPASSRLS;

COMMENT ON ROLE axonflow_app_role IS
    'AxonFlow application role for normal request traffic. Subject to RLS. '
    'Use AXONFLOW_DB_USE_APP_ROLE=true to opt agent/orchestrator into this role. '
    'Every transaction MUST issue SET LOCAL app.current_org_id before its first query.';

-- ============================================================================
-- Role: axonflow_platform_admin (LOGIN, BYPASSRLS)
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        CREATE ROLE axonflow_platform_admin LOGIN BYPASSRLS;
        RAISE NOTICE 'Created role: axonflow_platform_admin';
    ELSE
        RAISE NOTICE 'Role axonflow_platform_admin already exists (idempotent skip)';
        -- Make sure existing installs have BYPASSRLS (defensive against
        -- partial-apply state from earlier rehearsals).
        ALTER ROLE axonflow_platform_admin BYPASSRLS;
    END IF;
END
$$;

COMMENT ON ROLE axonflow_platform_admin IS
    'AxonFlow cross-org admin role for legitimate cross-tenant workers '
    '(community-saas sweep, usage aggregators, csaas-mirror, bridge, scripts). '
    'BYPASSRLS — handle with care. NEVER bind to a customer request path.';

-- ============================================================================
-- Grants on the public schema
-- ============================================================================
-- USAGE on schema is mandatory for any non-superuser role to see tables.
GRANT USAGE ON SCHEMA public TO axonflow_app_role;
GRANT USAGE ON SCHEMA public TO axonflow_platform_admin;

-- ============================================================================
-- Grants on existing tables for axonflow_app_role
-- ============================================================================
-- Grant the standard CRUD set on every table that currently exists. Future
-- migrations that CREATE TABLE need to add their own GRANT for axonflow_app_role
-- (or rely on a default-privileges rule — set below).
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO axonflow_app_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO axonflow_app_role;

-- ============================================================================
-- Grants on existing tables for axonflow_platform_admin
-- ============================================================================
-- Admin gets the same surface as app_role plus BYPASSRLS. Future tables also
-- need explicit GRANTs (the default-privileges below covers it for the table
-- owner's future CREATE TABLE statements).
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO axonflow_platform_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO axonflow_platform_admin;

-- ============================================================================
-- Default privileges — future tables created by the current table owner
-- ============================================================================
-- Without these, every new migration would need to add explicit GRANTs.
-- ALTER DEFAULT PRIVILEGES makes future CREATE TABLE statements auto-grant.
-- Scoped to the role that owns most tables (current_user at migration time).
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO axonflow_app_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO axonflow_app_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO axonflow_platform_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO axonflow_platform_admin;

-- ============================================================================
-- Smoke verification
-- ============================================================================
DO $$
DECLARE
    app_exists BOOLEAN;
    admin_exists BOOLEAN;
    admin_bypass BOOLEAN;
BEGIN
    SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') INTO app_exists;
    SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_platform_admin') INTO admin_exists;
    SELECT rolbypassrls FROM pg_roles WHERE rolname = 'axonflow_platform_admin' INTO admin_bypass;

    IF NOT app_exists THEN
        RAISE EXCEPTION 'Migration 098 failed: axonflow_app_role not created';
    END IF;
    IF NOT admin_exists THEN
        RAISE EXCEPTION 'Migration 098 failed: axonflow_platform_admin not created';
    END IF;
    IF admin_bypass IS NOT TRUE THEN
        RAISE EXCEPTION 'Migration 098 failed: axonflow_platform_admin does not have BYPASSRLS';
    END IF;

    RAISE NOTICE 'Migration 098 verified: app_role=%, admin=% (BYPASSRLS=%)',
                 app_exists, admin_exists, admin_bypass;
END
$$;

COMMIT;
