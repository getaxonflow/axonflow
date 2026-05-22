-- Migration 111: refresh COMMENT strings on v9 RLS helpers + policies
-- Date: 2026-05-22
--
-- ============================================================================
-- Why
-- ============================================================================
-- Re-issues COMMENT ON FUNCTION / TABLE / POLICY for every object whose
-- comment string was tightened to product-technical language. The source-file
-- changes in migs 101–109 only affect FRESH installs (the cleaned strings
-- land directly via CREATE FUNCTION / CREATE POLICY / COMMENT ON). Already-
-- deployed stacks carry the old strings in pg_description until this
-- migration UPDATEs them.
--
-- COMMENT ON ... IS replaces the existing pg_description row, so this
-- migration is idempotent: re-running on an already-clean stack is a
-- redundant UPDATE on pg_description (harmless cosmetic write).
--
-- Each block is guarded so the migration is safe in community-only
-- deployments that may lack the operator-managed enterprise schema.

BEGIN;

-- ============================================================================
-- POLICY comments
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'mcp_query_audits'
          AND policyname = 'mcp_query_audits_org_isolation'
    ) THEN
        EXECUTE $cmt$
        COMMENT ON POLICY mcp_query_audits_org_isolation ON mcp_query_audits IS
            'Per-org row visibility. org_id column added by migration 061; '
            'INSERT path (agent/audit_queue.go LogMCPQueryAudit) populates it from MCPQueryAuditEntry.'
        $cmt$;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'decision_chain'
          AND policyname = 'decision_chain_org_isolation'
    ) THEN
        EXECUTE $cmt$
        COMMENT ON POLICY decision_chain_org_isolation ON decision_chain IS
            'Per-org row visibility. Migration 102 normalized the expression from '
            'get_current_org_id() (mig 025) to direct current_setting() so '
            'smoke-verification grep on pg_policies.qual matches.'
        $cmt$;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'organizations'
          AND policyname = 'organizations_org_id_isolation'
    ) THEN
        EXECUTE $cmt$
        COMMENT ON POLICY organizations_org_id_isolation ON organizations IS
            'Per-org row visibility for axonflow_app_role traffic. '
            'Stacks alongside migration 018''s tenant_isolation_* policies (parity).'
        $cmt$;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'tenants'
          AND policyname = 'tenants_org_id_isolation'
    ) THEN
        EXECUTE $cmt$
        COMMENT ON POLICY tenants_org_id_isolation ON tenants IS
            'Per-org row visibility. tenants.org_id is NOT NULL (mig 062) and '
            'mig 100 ensures per-customer org_id values for the cs_* cohort.'
        $cmt$;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'community_saas_registrations'
          AND policyname = 'community_saas_registrations_org_id_isolation'
    ) THEN
        EXECUTE $cmt$
        COMMENT ON POLICY community_saas_registrations_org_id_isolation
            ON community_saas_registrations IS
            'Per-org row visibility for axonflow_app_role traffic. Pre-auth lookups '
            'go through csaas_auth_lookup SECURITY DEFINER helper (bypass); '
            'authenticated traffic sees only its own org via SET LOCAL '
            'app.current_org_id.'
        $cmt$;
    END IF;

    RAISE NOTICE 'Migration 111: refreshed POLICY comments on customer-facing RLS policies';
END
$$;

-- ============================================================================
-- TABLE comments
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'audit_retention_config' AND table_schema = 'public'
    ) THEN
        EXECUTE $cmt$
        COMMENT ON TABLE audit_retention_config IS
            'Per-org retention config. Migration 102 dropped the legacy '
            'app.is_admin admin_access policy. Cross-org access is now via '
            'axonflow_platform_admin (BYPASSRLS).'
        $cmt$;
        RAISE NOTICE 'Migration 111: refreshed TABLE comment on audit_retention_config';
    END IF;
END
$$;

-- ============================================================================
-- FUNCTION comments — migration 104 SaaS portal SECURITY DEFINER helpers
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_proc
        WHERE proname = 'portal_auth_lookup_org'
          AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        EXECUTE $cmt$
        COMMENT ON FUNCTION portal_auth_lookup_org(VARCHAR) IS
            'SECURITY DEFINER pre-auth lookup. Bypasses FORCE RLS on organizations '
            'for the credential-resolution path in HandleLogin. Returns only '
            'auth-needed columns, never the full row.'
        $cmt$;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_proc
        WHERE proname = 'portal_check_sso_availability'
          AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        EXECUTE $cmt$
        COMMENT ON FUNCTION portal_check_sso_availability(VARCHAR) IS
            'SECURITY DEFINER pre-auth SSO probe. Bypasses FORCE RLS on '
            'organizations + sso_configurations for the pre-login SSO-availability '
            'check.'
        $cmt$;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_proc
        WHERE proname = 'portal_default_tenant_id'
          AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        EXECUTE $cmt$
        COMMENT ON FUNCTION portal_default_tenant_id(VARCHAR) IS
            'SECURITY DEFINER variant of the mig 065 helper. Bypasses FORCE RLS '
            'on tenants for the post-auth tenant resolution called outside the '
            'user_sessions INSERT txn.'
        $cmt$;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_proc
        WHERE proname = 'register_org'
          AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        EXECUTE $cmt$
        COMMENT ON FUNCTION register_org(VARCHAR, VARCHAR, VARCHAR, INTEGER) IS
            'SECURITY DEFINER variant of the mig 062 register_org. Bypasses FORCE '
            'RLS on organizations for fire-and-forget auto-registration from '
            'registerTenantAndOrg.'
        $cmt$;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_proc
        WHERE proname = 'register_tenant'
          AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        EXECUTE $cmt$
        COMMENT ON FUNCTION register_tenant(VARCHAR, VARCHAR, VARCHAR) IS
            'SECURITY DEFINER variant of the mig 097 register_tenant. Bypasses '
            'FORCE RLS on tenants for fire-and-forget auto-registration from '
            'registerTenantAndOrg.'
        $cmt$;
    END IF;

    RAISE NOTICE 'Migration 111: refreshed FUNCTION comments on SaaS portal SECURITY DEFINER helpers';
END
$$;

-- ============================================================================
-- FUNCTION comment — migration 105 csaas_auth_lookup
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_proc
        WHERE proname = 'csaas_auth_lookup'
          AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        EXECUTE $cmt$
        COMMENT ON FUNCTION csaas_auth_lookup(VARCHAR) IS
            'SECURITY DEFINER pre-auth credential lookup for '
            'community_saas_registrations. Bypasses FORCE RLS for the '
            'credential-resolution SELECT in validateCommunityRegistration. '
            'Returns only auth-needed columns + org_id (so caller can set GUC).'
        $cmt$;
        RAISE NOTICE 'Migration 111: refreshed FUNCTION comment on csaas_auth_lookup';
    END IF;
END
$$;

-- ============================================================================
-- FUNCTION comments — migration 108 in-VPC enterprise auth helpers
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_proc
        WHERE proname = 'auth_lookup_api_key'
          AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        EXECUTE $cmt$
        COMMENT ON FUNCTION auth_lookup_api_key(TEXT) IS
            'SECURITY DEFINER pre-auth lookup for in-VPC enterprise auth. Mirrors '
            'the SaaS portal_auth_lookup_org pattern (mig 104). Bypasses FORCE RLS on '
            'api_keys + customers + pricing_tiers because the GUC app.current_org_id '
            'cannot be set before the lookup completes.'
        $cmt$;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_proc
        WHERE proname = 'auth_touch_api_key'
          AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        EXECUTE $cmt$
        COMMENT ON FUNCTION auth_touch_api_key(VARCHAR) IS
            'SECURITY DEFINER variant of the legacy updateAPIKeyLastUsed UPDATE. '
            'Called from the post-auth fire-and-forget goroutine which has no GUC; '
            'bypasses FORCE RLS on api_keys.'
        $cmt$;
    END IF;

    RAISE NOTICE 'Migration 111: refreshed FUNCTION comments on in-VPC enterprise auth helpers';
END
$$;

-- ============================================================================
-- FUNCTION comment — migration 109 auth_insert_api_key
-- ============================================================================
-- The other four mig-109 helpers (csaas_register_tenant, csaas_register_touch,
-- csaas_recovery_insert, portal_insert_api_key) already shipped with clean
-- comment strings, so they need no refresh here.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_proc
        WHERE proname = 'auth_insert_api_key'
          AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        EXECUTE $cmt$
        COMMENT ON FUNCTION auth_insert_api_key(VARCHAR, VARCHAR, VARCHAR, VARCHAR, INTEGER, VARCHAR) IS
            'SECURITY DEFINER INSERT into api_keys (in-VPC enterprise auth schema). '
            'Companion to auth_lookup_api_key / auth_touch_api_key — closes the '
            'INSERT side of the chicken-and-egg pattern (org_id is being minted in '
            'the same operator-API request). p_org_id populates the policy-key '
            'column so the row remains visible to direct app_role SELECTs under '
            'FORCE RLS. Community-mode databases lack the operator-managed api_keys '
            'schema — function is installed but never invoked there (caller is EE-only).'
        $cmt$;
        RAISE NOTICE 'Migration 111: refreshed FUNCTION comment on auth_insert_api_key';
    END IF;
END
$$;

COMMIT;
