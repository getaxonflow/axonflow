-- Migration 112: refresh COMMENT strings on v9 identity columns + saml_configurations
-- Date: 2026-05-22
--
-- ============================================================================
-- Why
-- ============================================================================
-- Re-issues COMMENT ON COLUMN / TABLE for every object whose comment string
-- was tightened to product-technical language in migrations 088-095. The
-- source-file changes only land on FRESH installs; already-deployed stacks
-- carry the previous strings in pg_description until this migration UPDATEs
-- them.
--
-- COMMENT ON ... IS replaces the existing pg_description row, so this
-- migration is idempotent: re-running on an already-clean stack is a
-- redundant UPDATE on pg_description (harmless cosmetic write).
--
-- Each block is guarded so the migration is safe in deployments that may
-- lack a given table or column (community-only / non-SSO / etc).

BEGIN;

-- ============================================================================
-- Migration 088 — credential client_id columns
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
    RAISE NOTICE 'Migration 112: refreshed credential client_id column comments';
END
$$;

-- ============================================================================
-- Migration 089 — audit-table client_id columns + llm_call_audits.org_id
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'audit_logs' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN audit_logs.client_id IS ''Credential identity column (req.Client.ID). Mirrors tenant_id today; tenant_id becomes a deprecated alias after the v9 soak window.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'mcp_query_audits' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN mcp_query_audits.client_id IS ''Credential identity column. Mirrors tenant_id today; tenant_id becomes a deprecated alias after the v9 soak window.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'llm_call_audits' AND column_name = 'org_id') THEN
        EXECUTE 'COMMENT ON COLUMN llm_call_audits.org_id IS ''Customer/account identity column. Added by migration 089; backfilled by migration 094 for pre-existing rows.''';
    END IF;
    RAISE NOTICE 'Migration 112: refreshed audit-table client_id + llm_call_audits.org_id comments';
END
$$;

-- ============================================================================
-- Migration 090 — policy-table client_id + policy_evaluations.org_id
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'static_policies' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN static_policies.client_id IS ''Credential identity column. The ''''global'''' sentinel is preserved verbatim for system-wide policies that apply across all clients.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'dynamic_policies' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN dynamic_policies.client_id IS ''Credential identity column. The ''''global'''' sentinel is preserved verbatim for system-wide policies that apply across all clients.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'policy_evaluations' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN policy_evaluations.client_id IS ''Credential identity column. Separate from the legacy organization_id UUID column.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'policy_evaluations' AND column_name = 'org_id') THEN
        EXECUTE 'COMMENT ON COLUMN policy_evaluations.org_id IS ''Customer/account identity (VARCHAR). Mirrors org_id shape used in audit_logs/static_policies; coexists with the legacy organization_id UUID column.''';
    END IF;
    RAISE NOTICE 'Migration 112: refreshed policy-table client_id + org_id comments';
END
$$;

-- ============================================================================
-- Migration 091 — service_identities.client_id
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'service_identities' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN service_identities.client_id IS ''Credential/service identity column. Mirrors tenant_id for service-to-service auth callers.''';
        RAISE NOTICE 'Migration 112: refreshed service_identities.client_id comment';
    END IF;
END
$$;

-- ============================================================================
-- Migration 092 — execution_history.client_id
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'execution_history' AND column_name = 'client_id') THEN
        EXECUTE 'COMMENT ON COLUMN execution_history.client_id IS ''Credential identity column. Predates the v9 migration; backfilled by 092 for rows with empty client_id. tenant_id remains as a deprecated alias.''';
        RAISE NOTICE 'Migration 112: refreshed execution_history.client_id comment';
    END IF;
END
$$;

-- ============================================================================
-- Migration 093 — saml_configurations TABLE + org_id column
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'saml_configurations' AND table_schema = 'public') THEN
        EXECUTE 'COMMENT ON TABLE saml_configurations IS ''SAML SSO configurations per organization. Org-scoped — does NOT carry client_id; one IdP per org by design.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'saml_configurations' AND column_name = 'org_id') THEN
        EXECUTE 'COMMENT ON COLUMN saml_configurations.org_id IS ''Customer/account identity column. UNIQUE NOT NULL since migration 002 — one IdP per org by design.''';
        RAISE NOTICE 'Migration 112: refreshed saml_configurations TABLE + org_id comments';
    END IF;
END
$$;

-- ============================================================================
-- Migration 095 — usage_records column classifications
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'usage_records' AND column_name = 'team_id') THEN
        EXECUTE 'COMMENT ON COLUMN usage_records.team_id IS ''ATTRIBUTION TAG (not part of the v9 identity model). Cost/budget grouping inside an org — orthogonal to org_id/client_id/user_id. Do NOT migrate team_id into the v9 identity model — design a separate team/workspace feature if/when product needs it.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'usage_records' AND column_name = 'org_id') THEN
        EXECUTE 'COMMENT ON COLUMN usage_records.org_id IS ''Customer/account identity column. Populated by request handlers; backfilled via 094 Pass-2 deployment-org fallback for historical rows.''';
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'usage_records' AND column_name = 'tenant_id') THEN
        EXECUTE 'COMMENT ON COLUMN usage_records.tenant_id IS ''Credential alias (deprecated). Equivalent to client_id; tracked as a compatibility column until a future major version drops it.''';
        RAISE NOTICE 'Migration 112: refreshed usage_records column comments';
    END IF;
END
$$;

COMMIT;
