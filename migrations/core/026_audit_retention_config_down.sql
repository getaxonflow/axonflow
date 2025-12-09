-- Rollback Migration: SEBI Audit Retention Configuration
-- Date: 2025-12-07
-- Purpose: Remove audit retention configuration tables and functions

-- Drop view
DROP VIEW IF EXISTS audit_retention_summary;

-- Drop functions
DROP FUNCTION IF EXISTS cleanup_expired_audit_records(VARCHAR, INTEGER);
DROP FUNCTION IF EXISTS get_effective_retention_days(INTEGER, VARCHAR);

-- Drop RLS policies
DROP POLICY IF EXISTS audit_retention_config_admin_access ON audit_retention_config;
DROP POLICY IF EXISTS audit_retention_config_org_isolation ON audit_retention_config;

-- Drop tables (in reverse dependency order)
DROP TABLE IF EXISTS audit_archive;
DROP TABLE IF EXISTS audit_retention_config;
DROP TABLE IF EXISTS audit_retention_defaults;

-- Success message
DO $$
BEGIN
    RAISE NOTICE 'SEBI Audit Retention Configuration Rollback Complete';
END $$;
