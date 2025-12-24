-- Migration 030: Policy Tier and Category Architecture
-- Date: 2025-12-24
-- Purpose: Add tier hierarchy and category classification to policies
-- Related: ADR-020 - Unified Policy Architecture, Issue #724

-- =============================================================================
-- PHASE 1: Add tier and organization_id columns to static_policies
-- =============================================================================

-- Add tier column with default 'tenant' for backward compatibility
-- New system policies will be seeded with tier='system' in migration 031
ALTER TABLE static_policies
    ADD COLUMN IF NOT EXISTS tier VARCHAR(20) DEFAULT 'tenant'
        CHECK (tier IN ('system', 'organization', 'tenant'));

-- Add organization_id for org-tier policies (Enterprise feature)
-- NULL for system and tenant-tier policies
ALTER TABLE static_policies
    ADD COLUMN IF NOT EXISTS organization_id UUID;

-- Add priority for policy evaluation order (higher = evaluated first)
ALTER TABLE static_policies
    ADD COLUMN IF NOT EXISTS priority INTEGER DEFAULT 50;

-- Add tags for flexible categorization (compliance labels, etc.)
ALTER TABLE static_policies
    ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '[]';

-- Add audit columns if not present
ALTER TABLE static_policies
    ADD COLUMN IF NOT EXISTS created_by VARCHAR(255);

ALTER TABLE static_policies
    ADD COLUMN IF NOT EXISTS updated_by VARCHAR(255);

-- Add soft delete column for non-system policies
ALTER TABLE static_policies
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP WITH TIME ZONE;

-- =============================================================================
-- PHASE 2: Add tier and organization_id columns to dynamic_policies
-- =============================================================================

-- Add tier column with default 'tenant' for backward compatibility
ALTER TABLE dynamic_policies
    ADD COLUMN IF NOT EXISTS tier VARCHAR(20) DEFAULT 'tenant'
        CHECK (tier IN ('system', 'organization', 'tenant'));

-- Add organization_id for org-tier policies
ALTER TABLE dynamic_policies
    ADD COLUMN IF NOT EXISTS organization_id UUID;

-- Add category column for dynamic policy classification
-- Uses 'dynamic-*' categories defined in ADR-020
ALTER TABLE dynamic_policies
    ADD COLUMN IF NOT EXISTS category VARCHAR(50);

-- Add tags for flexible categorization
ALTER TABLE dynamic_policies
    ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '[]';

-- Add soft delete column
ALTER TABLE dynamic_policies
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP WITH TIME ZONE;

-- =============================================================================
-- PHASE 3: Create policy_overrides table (Enterprise feature)
-- =============================================================================
-- Allows Enterprise customers to override system policy actions without
-- modifying the policy pattern itself.

CREATE TABLE IF NOT EXISTS policy_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Reference to the policy being overridden
    policy_id UUID NOT NULL,
    policy_type VARCHAR(20) NOT NULL CHECK (policy_type IN ('static', 'dynamic')),

    -- Scope of the override (org-level or tenant-level)
    organization_id UUID,
    tenant_id VARCHAR(100),

    -- What's being overridden
    action_override VARCHAR(20) CHECK (action_override IN ('block', 'warn', 'log')),
    enabled_override BOOLEAN,

    -- Audit and governance
    override_reason TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE, -- Optional auto-revert
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by VARCHAR(255),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Scope validation: must be either org-level OR tenant-level
    CONSTRAINT valid_override_scope CHECK (
        (organization_id IS NOT NULL AND tenant_id IS NULL) OR
        (tenant_id IS NOT NULL)
    )
);

-- Add RLS policy for multi-tenant isolation
ALTER TABLE policy_overrides ENABLE ROW LEVEL SECURITY;

CREATE POLICY policy_overrides_tenant_isolation ON policy_overrides
    USING (
        tenant_id = current_setting('app.tenant_id', true)
        OR organization_id IN (
            SELECT org_id::uuid FROM organizations
            WHERE id::text = current_setting('app.tenant_id', true)
        )
    );

-- =============================================================================
-- PHASE 4: Create static_policy_versions table
-- =============================================================================
-- Version history for static policies (complements existing policy_versions
-- table for dynamic policies created in migration 022).

CREATE TABLE IF NOT EXISTS static_policy_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Reference to the static policy
    policy_id UUID NOT NULL,
    version INTEGER NOT NULL,

    -- Complete policy state at this version
    snapshot JSONB NOT NULL,

    -- Change metadata
    change_type VARCHAR(50) NOT NULL CHECK (
        change_type IN ('create', 'update', 'delete', 'enable', 'disable', 'override')
    ),
    change_summary TEXT,
    changed_by VARCHAR(255),
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Ensure unique version per policy
    CONSTRAINT unique_static_policy_version UNIQUE (policy_id, version)
);

-- Add RLS policy for multi-tenant isolation
ALTER TABLE static_policy_versions ENABLE ROW LEVEL SECURITY;

CREATE POLICY static_policy_versions_tenant_isolation ON static_policy_versions
    USING (
        policy_id IN (
            SELECT id FROM static_policies
            WHERE tenant_id = current_setting('app.tenant_id', true)
            OR tier = 'system'
        )
    );

-- =============================================================================
-- PHASE 5: Create indexes for new columns
-- =============================================================================

-- Static policies indexes
CREATE INDEX IF NOT EXISTS idx_static_policies_tier ON static_policies(tier);
CREATE INDEX IF NOT EXISTS idx_static_policies_organization ON static_policies(organization_id) WHERE organization_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_static_policies_deleted ON static_policies(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_static_policies_tier_category ON static_policies(tier, category) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_static_policies_priority ON static_policies(priority DESC) WHERE enabled = true;

-- Dynamic policies indexes
CREATE INDEX IF NOT EXISTS idx_dynamic_policies_tier ON dynamic_policies(tier);
CREATE INDEX IF NOT EXISTS idx_dynamic_policies_organization ON dynamic_policies(organization_id) WHERE organization_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_dynamic_policies_category ON dynamic_policies(category) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_dynamic_policies_deleted ON dynamic_policies(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_dynamic_policies_tier_category ON dynamic_policies(tier, category) WHERE enabled = true;

-- Policy overrides indexes
CREATE INDEX IF NOT EXISTS idx_policy_overrides_policy ON policy_overrides(policy_id, policy_type);
CREATE INDEX IF NOT EXISTS idx_policy_overrides_org ON policy_overrides(organization_id) WHERE organization_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_policy_overrides_tenant ON policy_overrides(tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_policy_overrides_expires ON policy_overrides(expires_at) WHERE expires_at IS NOT NULL;

-- Static policy versions indexes
CREATE INDEX IF NOT EXISTS idx_static_policy_versions_policy ON static_policy_versions(policy_id);
CREATE INDEX IF NOT EXISTS idx_static_policy_versions_changed_at ON static_policy_versions(changed_at);
CREATE INDEX IF NOT EXISTS idx_static_policy_versions_policy_version ON static_policy_versions(policy_id, version DESC);

-- =============================================================================
-- PHASE 6: Add triggers for updated_at
-- =============================================================================

-- Trigger for policy_overrides
DROP TRIGGER IF EXISTS update_policy_overrides_updated_at ON policy_overrides;
CREATE TRIGGER update_policy_overrides_updated_at
    BEFORE UPDATE ON policy_overrides
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Documentation comments
-- =============================================================================

COMMENT ON COLUMN static_policies.tier IS 'Policy tier: system (immutable), organization (enterprise), or tenant (customer)';
COMMENT ON COLUMN static_policies.organization_id IS 'Organization UUID for organization-tier policies (Enterprise only)';
COMMENT ON COLUMN static_policies.priority IS 'Evaluation priority: higher values evaluated first (default: 50)';
COMMENT ON COLUMN static_policies.tags IS 'JSONB array of tags for flexible categorization (e.g., compliance:hipaa)';
COMMENT ON COLUMN static_policies.deleted_at IS 'Soft delete timestamp (NULL = active)';

COMMENT ON COLUMN dynamic_policies.tier IS 'Policy tier: system (immutable), organization (enterprise), or tenant (customer)';
COMMENT ON COLUMN dynamic_policies.organization_id IS 'Organization UUID for organization-tier policies (Enterprise only)';
COMMENT ON COLUMN dynamic_policies.category IS 'Category classification: dynamic-risk, dynamic-compliance, etc.';
COMMENT ON COLUMN dynamic_policies.tags IS 'JSONB array of tags for flexible categorization';
COMMENT ON COLUMN dynamic_policies.deleted_at IS 'Soft delete timestamp (NULL = active)';

COMMENT ON TABLE policy_overrides IS 'Enterprise feature: Override system policy actions without modifying patterns';
COMMENT ON COLUMN policy_overrides.action_override IS 'Override action: block, warn, or log';
COMMENT ON COLUMN policy_overrides.expires_at IS 'Optional auto-revert timestamp for temporary overrides';

COMMENT ON TABLE static_policy_versions IS 'Version history for static policy audit trail';
COMMENT ON COLUMN static_policy_versions.snapshot IS 'Complete policy state at this version (JSONB)';
COMMENT ON COLUMN static_policy_versions.change_type IS 'Type of change: create, update, delete, enable, disable, override';

-- Migration complete
-- Next: 031_seed_system_policies.sql (seeds all 63 system policies with categories)
