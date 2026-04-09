-- Migration 065: Customer portal tenant identity
-- Date: 2026-04-08
-- Context: Multi-tenant SaaS — customer portal must distinguish between
-- the org (organization/entitlement boundary) and the tenant (a specific
-- environment within the org that scopes data: prod, staging, dev, etc.).
--
-- Before this migration the customer portal aliased tenant_id := org_id in
-- auth.go with the comment "organizations table doesn't have tenant_id
-- column". That collapsed two concepts into one and prevented a single
-- portal org from drilling into workflows belonging to different tenants.
--
-- This migration:
--   1. Adds a tenant_id column to user_sessions (nullable for backwards
--      compatibility; auth layer defaults to org_id when unset).
--   2. Ensures every org has a default tenant row in the `tenants` table
--      (tenants was created in migration 062) so the portal can always
--      resolve a tenant for every session.
--   3. Adds a helper SQL function portal_default_tenant_id() used by auth.

-- =============================================================================
-- user_sessions.tenant_id
-- =============================================================================

ALTER TABLE user_sessions
    ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id
    ON user_sessions(tenant_id);

COMMENT ON COLUMN user_sessions.tenant_id IS
    'Active tenant for this portal session. A single org can have multiple tenants (prod, staging, dev); this column tracks which one the user is currently viewing. Nullable for legacy sessions and defaults to org_id on migration.';

-- Backfill: copy org_id into tenant_id for existing sessions so they keep
-- working after the portal auth change starts reading session.tenant_id.
UPDATE user_sessions
SET tenant_id = org_id
WHERE tenant_id IS NULL;

-- =============================================================================
-- Default tenant row per existing org
-- =============================================================================

-- For every organization that doesn't already have a tenant with
-- tenant_id = org_id, insert one. This gives every existing portal org a
-- default tenant so login can resolve tenant_id deterministically.
-- Only runs if the tenants table exists (migration 062 may not have run
-- in community-only deployments).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tenants') THEN
        INSERT INTO tenants (tenant_id, org_id, name, environment)
        SELECT o.org_id, o.org_id, o.name, 'production'
        FROM organizations o
        WHERE NOT EXISTS (
            SELECT 1 FROM tenants t
            WHERE t.tenant_id = o.org_id AND t.org_id = o.org_id
        );
    END IF;
END $$;

-- =============================================================================
-- Helper function: resolve default tenant for an org
-- =============================================================================

CREATE OR REPLACE FUNCTION portal_default_tenant_id(p_org_id VARCHAR(255))
RETURNS VARCHAR(255) AS $$
DECLARE
    result VARCHAR(255);
BEGIN
    -- Prefer the tenant with the same tenant_id as org_id (canonical default)
    SELECT tenant_id INTO result
    FROM tenants
    WHERE org_id = p_org_id AND tenant_id = p_org_id
    LIMIT 1;

    IF result IS NOT NULL THEN
        RETURN result;
    END IF;

    -- Otherwise return the oldest tenant for this org
    SELECT tenant_id INTO result
    FROM tenants
    WHERE org_id = p_org_id
    ORDER BY created_at ASC
    LIMIT 1;

    -- Fall back to org_id if no tenants exist at all (e.g. community deployments
    -- without the tenants table populated).
    IF result IS NULL THEN
        result := p_org_id;
    END IF;

    RETURN result;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION portal_default_tenant_id IS
    'Returns the default tenant_id for a portal session when the user has not explicitly selected one. Prefers tenant_id = org_id (canonical default) and falls back to the oldest tenant, then org_id itself.';

-- Success
DO $$
BEGIN
    RAISE NOTICE 'Migration 065: Customer portal tenant identity — added tenant_id to user_sessions, backfilled default tenants';
END $$;
