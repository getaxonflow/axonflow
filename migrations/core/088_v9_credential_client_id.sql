-- Migration 088: v9 credential client_id columns (additive)
-- Date: 2026-05-19
--
-- Adds client_id as a deprecation-safe alias for tenant_id on the
-- three credential-class tables, backfilling client_id = tenant_id.
-- Pure additive: no NOT NULL, no FORCE RLS, no FK changes.
--
-- Classification:
--   community_saas_registrations.tenant_id — credential PK (Basic Auth username)
--   tenants.tenant_id                       — credential mapping
--   plugin_user_licenses.tenant_id          — credential (Plugin Pro stays
--                                             credential-scoped, not org-scoped,
--                                             until product/billing decides otherwise)
--
-- All three carry the v9 credential-identity meaning today, so each gets a
-- client_id column populated from tenant_id. tenant_id remains as the
-- v9-compatibility alias until v10.
--
-- Numbering note: this would have been 086 (next sequential after core/085),
-- but the migration runner (platform/agent/migration_helpers.go) keys
-- schema_migrations by version string alone, so a core/086 would silently
-- shadow the existing community-saas/086_community_saas_bridge_rds_iam_auth.
-- See issue filed alongside this PR for the runner fix; 088 was chosen as
-- the next non-colliding sequential number.
--
-- Idempotency: every statement uses IF NOT EXISTS / WHERE-empty guards so
-- second-run is a no-op. Backfill UPDATE only writes rows where client_id
-- is NULL or empty, so re-running never overwrites established values.
--
-- Rollback: paired scripts/v9_rollback/088_rollback.sql drops the columns
-- and indexes added here.
--
-- Depends on: 068_community_saas_registrations, 062_tenants_table, 077_plugin_user_licenses

-- ============================================================================
-- community_saas_registrations
-- ============================================================================
-- The Basic Auth username (cs_<uuid>) lives in tenant_id today. Adding
-- client_id with the same value gives the v9 auth path a forward-compatible
-- column without disturbing the live primary key.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'community_saas_registrations') THEN
        ALTER TABLE community_saas_registrations
            ADD COLUMN IF NOT EXISTS client_id VARCHAR(255);

        UPDATE community_saas_registrations
            SET client_id = tenant_id
            WHERE (client_id IS NULL OR client_id = '')
              AND tenant_id IS NOT NULL
              AND tenant_id <> '';

        -- Unique constraint mirrors the tenant_id PK so v9 lookups by
        -- client_id are O(1) without depending on the PK column name.
        CREATE UNIQUE INDEX IF NOT EXISTS uq_csaas_reg_client_id
            ON community_saas_registrations(client_id)
            WHERE client_id IS NOT NULL;

        RAISE NOTICE 'Migration 088: community_saas_registrations.client_id added + backfilled';
    ELSE
        RAISE NOTICE 'Migration 088: community_saas_registrations missing — skipping (likely non-community-saas deployment)';
    END IF;
END $$;

-- ============================================================================
-- tenants
-- ============================================================================
-- tenants.tenant_id is the credential mapping for in-VPC Enterprise + self-
-- hosted Community deployments. Same treatment.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tenants') THEN
        ALTER TABLE tenants
            ADD COLUMN IF NOT EXISTS client_id VARCHAR(255);

        UPDATE tenants
            SET client_id = tenant_id
            WHERE (client_id IS NULL OR client_id = '')
              AND tenant_id IS NOT NULL
              AND tenant_id <> '';

        CREATE INDEX IF NOT EXISTS idx_tenants_client_id
            ON tenants(client_id)
            WHERE client_id IS NOT NULL;

        RAISE NOTICE 'Migration 088: tenants.client_id added + backfilled';
    ELSE
        RAISE NOTICE 'Migration 088: tenants missing — skipping';
    END IF;
END $$;

-- ============================================================================
-- plugin_user_licenses
-- ============================================================================
-- plugin_user_licenses.tenant_id has a FK to community_saas_registrations(tenant_id).
-- We only ADD client_id and backfill; we DO NOT add an FK on client_id here
-- because the parent table's PK is still tenant_id. The v9 FK switch lands
-- in a follow-up migration once the parent's authoritative key swaps.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'plugin_user_licenses') THEN
        ALTER TABLE plugin_user_licenses
            ADD COLUMN IF NOT EXISTS client_id VARCHAR(255);

        UPDATE plugin_user_licenses
            SET client_id = tenant_id
            WHERE (client_id IS NULL OR client_id = '')
              AND tenant_id IS NOT NULL
              AND tenant_id <> '';

        -- Hot enforcement-path index. plugin_user_licenses is read on every
        -- request via the agent middleware; the existing tenant_id index in
        -- 077 stays so legacy callers keep their fast path.
        CREATE INDEX IF NOT EXISTS idx_plugin_lic_client_id
            ON plugin_user_licenses(client_id)
            WHERE client_id IS NOT NULL;

        -- Active-only partial index mirrors idx_plugin_lic_active from 077
        -- so v9 callers reading by client_id keep parity.
        CREATE INDEX IF NOT EXISTS idx_plugin_lic_client_active
            ON plugin_user_licenses(client_id)
            WHERE revoked_at IS NULL AND client_id IS NOT NULL;

        RAISE NOTICE 'Migration 088: plugin_user_licenses.client_id added + backfilled';
    ELSE
        RAISE NOTICE 'Migration 088: plugin_user_licenses missing — skipping';
    END IF;
END $$;

-- ============================================================================
-- Column documentation
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'community_saas_registrations' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN community_saas_registrations.client_id IS ''Credential/app identity column. Equal to tenant_id until the tenant_id alias is removed in a future major version.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'tenants' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN tenants.client_id IS ''Credential/app identity column. Equal to tenant_id until the tenant_id alias is removed in a future major version.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'plugin_user_licenses' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN plugin_user_licenses.client_id IS ''Credential identity column. Plugin Pro stays credential-scoped; any move to org-scoped Pro is a separate billing migration.''';
    END IF;
END $$;

-- TODO: once the code-side credential plumbing lands, swap the FK in
-- plugin_user_licenses(tenant_id) to plugin_user_licenses(client_id) and
-- rename indexes accordingly.

DO $$
BEGIN
    RAISE NOTICE 'Migration 088 complete — v9 credential client_id additive layer';
END $$;
