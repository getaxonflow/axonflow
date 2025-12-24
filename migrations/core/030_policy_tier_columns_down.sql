-- Migration 030 DOWN: Rollback Policy Tier and Category Architecture
-- Date: 2025-12-24
-- Purpose: Rollback tier hierarchy and category classification

-- =============================================================================
-- Drop indexes first (reverse order of creation)
-- =============================================================================

DROP INDEX IF EXISTS idx_static_policy_versions_policy_version;
DROP INDEX IF EXISTS idx_static_policy_versions_changed_at;
DROP INDEX IF EXISTS idx_static_policy_versions_policy;

DROP INDEX IF EXISTS idx_policy_overrides_expires;
DROP INDEX IF EXISTS idx_policy_overrides_tenant;
DROP INDEX IF EXISTS idx_policy_overrides_org;
DROP INDEX IF EXISTS idx_policy_overrides_policy;

DROP INDEX IF EXISTS idx_dynamic_policies_tier_category;
DROP INDEX IF EXISTS idx_dynamic_policies_deleted;
DROP INDEX IF EXISTS idx_dynamic_policies_category;
DROP INDEX IF EXISTS idx_dynamic_policies_organization;
DROP INDEX IF EXISTS idx_dynamic_policies_tier;

DROP INDEX IF EXISTS idx_static_policies_priority;
DROP INDEX IF EXISTS idx_static_policies_tier_category;
DROP INDEX IF EXISTS idx_static_policies_deleted;
DROP INDEX IF EXISTS idx_static_policies_organization;
DROP INDEX IF EXISTS idx_static_policies_tier;

-- =============================================================================
-- Drop triggers
-- =============================================================================

DROP TRIGGER IF EXISTS update_policy_overrides_updated_at ON policy_overrides;

-- =============================================================================
-- Drop new tables
-- =============================================================================

DROP TABLE IF EXISTS static_policy_versions;
DROP TABLE IF EXISTS policy_overrides;

-- =============================================================================
-- Remove columns from dynamic_policies (reverse order of addition)
-- =============================================================================

ALTER TABLE dynamic_policies DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE dynamic_policies DROP COLUMN IF EXISTS tags;
ALTER TABLE dynamic_policies DROP COLUMN IF EXISTS category;
ALTER TABLE dynamic_policies DROP COLUMN IF EXISTS organization_id;
ALTER TABLE dynamic_policies DROP COLUMN IF EXISTS tier;

-- =============================================================================
-- Remove columns from static_policies (reverse order of addition)
-- =============================================================================

ALTER TABLE static_policies DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE static_policies DROP COLUMN IF EXISTS updated_by;
ALTER TABLE static_policies DROP COLUMN IF EXISTS created_by;
ALTER TABLE static_policies DROP COLUMN IF EXISTS tags;
ALTER TABLE static_policies DROP COLUMN IF EXISTS priority;
ALTER TABLE static_policies DROP COLUMN IF EXISTS organization_id;
ALTER TABLE static_policies DROP COLUMN IF EXISTS tier;

-- Rollback complete
