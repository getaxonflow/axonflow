-- Migration 065 DOWN: Remove customer portal tenant identity changes

DROP FUNCTION IF EXISTS portal_default_tenant_id(VARCHAR);

DROP INDEX IF EXISTS idx_sessions_tenant_id;
ALTER TABLE user_sessions DROP COLUMN IF EXISTS tenant_id;

-- Intentionally do NOT remove the auto-inserted tenant rows — keeping them
-- is safe even after rollback because the tenants table was introduced in
-- migration 062 and is expected to contain these rows.
