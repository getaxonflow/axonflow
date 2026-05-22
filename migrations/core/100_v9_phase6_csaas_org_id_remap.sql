-- Migration 100: re-apply cs_* org_id remap for any drift since 094
-- Date: 2026-05-20
--
-- Migration 094 did the heavy lift: it remapped every existing
-- Community-SaaS customer row from the shared constant
-- org_id = 'community-saas' to org_id = cs_<uuid>, across the multi-tenant
-- customer-data tables (community_saas_registrations, tenants, audit_logs,
-- mcp_query_audits, static_policies, dynamic_policies, agent_audit_logs,
-- service_identities, execution_history, policy_evaluations).
--
-- 094 closed the historical state. Between then and the code-deploy in this
-- migration's release, the Community-SaaS write path
-- (platform/agent/community_saas_register.go + auth.go) was STILL writing the
-- shared constant for every new registration / recovery / first-authenticated
-- request. This release ships the code change that stops writing the
-- constant; this migration re-runs the cs_* remap UPDATEs so any rows landed
-- between 094-deploy and the code-deploy converge to the per-customer org_id.
--
-- Idempotency: every UPDATE has a WHERE-old-value-equals-'community-saas' AND
-- tenant_id-LIKE-'cs_%' guard. Re-running on an already-converged DB is a
-- no-op (the WHERE filters out rows that already have the cs_* org_id). This
-- is the same pattern migration 094 uses.
--
-- Scope: ONLY the cs_* cohort. This migration does not touch:
--   - org_id rows for the self-hosted / in-VPC cohort (those were backfilled
--     from app.deployment_org_id in migration 094 Pass 2)
--   - the 'global' sentinel rows in static_policies / dynamic_policies
--   - any DDB telemetry tables (SoX-scoped)
--   - any organizations table seed rows (094's Pass-1 PREP block already
--     inserted them; ON CONFLICT DO NOTHING makes re-running safe but this
--     migration does not need to re-seed)
--
-- Rollback: paired 100_v9_phase6_csaas_org_id_remap_down.sql restores
-- org_id='community-saas' on rows whose tenant_id LIKE 'cs_%' AND
-- org_id = tenant_id (the cohort this migration touched). It matches the
-- pattern in 094_down.sql.
--
-- Depends on: 094_v9_org_id_backfill (already shipped; this is a
--             defense-in-depth re-application).

-- ============================================================================
-- PASS 1A: community_saas_registrations — set org_id = client_id for cs_* rows
-- ============================================================================
DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'community_saas_registrations')
       AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'community_saas_registrations' AND column_name = 'client_id') THEN
        UPDATE community_saas_registrations
            SET org_id = client_id
            WHERE org_id = 'community-saas'
              AND client_id LIKE 'cs\_%' ESCAPE '\';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 100 Pass-1A: community_saas_registrations org_id remapped on % cs_* rows (drift since 094)', rows_updated;
    ELSE
        RAISE NOTICE 'Migration 100 Pass-1A: community_saas_registrations or client_id column missing — skipping';
    END IF;
END $$;

-- ============================================================================
-- PASS 1A-seed: organizations rows for any cs_* identity that landed post-094
-- ============================================================================
-- tenants.org_id has a FK fk_tenants_org → organizations(org_id). Any cs_*
-- identity that didn't exist when 094 ran needs an organizations row before
-- Pass 1B can set tenants.org_id = tenant_id. ON CONFLICT DO NOTHING makes
-- this safe for already-seeded rows.
DO $$
DECLARE
    inserted_csaas INTEGER := 0;
    inserted_tenants INTEGER := 0;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'organizations') THEN
        RAISE NOTICE 'Migration 100 Pass-1A-seed: organizations missing — skipping';
        RETURN;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'community_saas_registrations') THEN
        INSERT INTO organizations (org_id, name, tier, max_nodes, license_key)
            SELECT DISTINCT tenant_id, COALESCE(label, tenant_id), 'Community', 999999, ''
            FROM community_saas_registrations
            WHERE tenant_id LIKE 'cs\_%' ESCAPE '\'
        ON CONFLICT (org_id) DO NOTHING;
        GET DIAGNOSTICS inserted_csaas = ROW_COUNT;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tenants') THEN
        INSERT INTO organizations (org_id, name, tier, max_nodes, license_key)
            SELECT DISTINCT tenant_id, COALESCE(name, tenant_id), 'Community', 999999, ''
            FROM tenants
            WHERE tenant_id LIKE 'cs\_%' ESCAPE '\'
        ON CONFLICT (org_id) DO NOTHING;
        GET DIAGNOSTICS inserted_tenants = ROW_COUNT;
    END IF;

    RAISE NOTICE 'Migration 100 Pass-1A-seed: % + % organizations rows inserted for post-094 drift (registrations + tenants)', inserted_csaas, inserted_tenants;
END $$;

-- ============================================================================
-- PASS 1B: tenants — set org_id = tenant_id for cs_* rows
-- ============================================================================
DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tenants') THEN
        UPDATE tenants
            SET org_id = tenant_id
            WHERE (org_id IS NULL OR org_id = '' OR org_id = 'community-saas')
              AND tenant_id LIKE 'cs\_%' ESCAPE '\';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 100 Pass-1B: tenants org_id remapped on % cs_* rows (drift since 094)', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- PASS 1C: audit_logs — set org_id from tenant_id for cs_* rows
-- ============================================================================
DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_logs') THEN
        UPDATE audit_logs
            SET org_id = tenant_id
            WHERE (org_id IS NULL OR org_id = '' OR org_id = 'community-saas')
              AND tenant_id LIKE 'cs\_%' ESCAPE '\';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 100 Pass-1C: audit_logs org_id remapped on % cs_* rows (drift since 094)', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- PASS 1D: mcp_query_audits — same pattern
-- ============================================================================
DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mcp_query_audits') THEN
        UPDATE mcp_query_audits
            SET org_id = tenant_id
            WHERE (org_id IS NULL OR org_id = '' OR org_id = 'community-saas')
              AND tenant_id LIKE 'cs\_%' ESCAPE '\';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 100 Pass-1D: mcp_query_audits org_id remapped on % cs_* rows (drift since 094)', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- PASS 1E: static_policies — set org_id = tenant_id for cs_* rows
-- ============================================================================
-- Skip the 'global' sentinel rows — system-wide, no per-customer org_id.
DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'static_policies') THEN
        UPDATE static_policies
            SET org_id = tenant_id
            WHERE (org_id IS NULL OR org_id = '' OR org_id = 'community-saas')
              AND tenant_id LIKE 'cs\_%' ESCAPE '\'
              AND tenant_id <> 'global';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 100 Pass-1E: static_policies org_id remapped on % cs_* rows (drift since 094)', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- PASS 1F: dynamic_policies — same pattern
-- ============================================================================
DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'dynamic_policies') THEN
        UPDATE dynamic_policies
            SET org_id = tenant_id
            WHERE (org_id IS NULL OR org_id = '' OR org_id = 'community-saas')
              AND tenant_id LIKE 'cs\_%' ESCAPE '\'
              AND tenant_id <> 'global';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 100 Pass-1F: dynamic_policies org_id remapped on % cs_* rows (drift since 094)', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- PASS 1G: agent_audit_logs — backfill via client_id for cs_* rows
-- ============================================================================
DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_audit_logs')
       AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'agent_audit_logs' AND column_name = 'client_id') THEN
        UPDATE agent_audit_logs
            SET org_id = client_id
            WHERE (org_id IS NULL OR org_id = '' OR org_id = 'community-saas')
              AND client_id LIKE 'cs\_%' ESCAPE '\';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 100 Pass-1G: agent_audit_logs org_id remapped on % cs_* rows (drift since 094)', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- PASS 1H: service_identities
-- ============================================================================
DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'service_identities') THEN
        UPDATE service_identities
            SET org_id = tenant_id
            WHERE (org_id IS NULL OR org_id = '' OR org_id = 'community-saas')
              AND tenant_id LIKE 'cs\_%' ESCAPE '\';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 100 Pass-1H: service_identities org_id remapped on % cs_* rows (drift since 094)', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- PASS 1I: execution_history
-- ============================================================================
DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'execution_history') THEN
        UPDATE execution_history
            SET org_id = tenant_id
            WHERE (org_id IS NULL OR org_id = '' OR org_id = 'community-saas')
              AND tenant_id LIKE 'cs\_%' ESCAPE '\';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 100 Pass-1I: execution_history org_id remapped on % cs_* rows (drift since 094)', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- PASS 1J: policy_evaluations (org_id added in 090)
-- ============================================================================
DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'policy_evaluations')
       AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'policy_evaluations' AND column_name = 'org_id') THEN
        UPDATE policy_evaluations
            SET org_id = tenant_id
            WHERE (org_id IS NULL OR org_id = '' OR org_id = 'community-saas')
              AND tenant_id LIKE 'cs\_%' ESCAPE '\';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 100 Pass-1J: policy_evaluations org_id remapped on % cs_* rows (drift since 094)', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- Verification report
-- ============================================================================
-- After this migration runs AND the code-deploy is live, every table below
-- should report 0 rows with org_id='community-saas' for any tenant whose
-- ID matches cs_*. Non-zero counts mean either (a) a non-cs_* row legitimately
-- carries the shared constant (e.g. global sentinels — skipped above), or
-- (b) a write path the code-deploy missed.
DO $$
DECLARE
    rec RECORD;
    remaining INTEGER;
BEGIN
    FOR rec IN
        SELECT t AS tname, c AS col FROM (VALUES
            ('community_saas_registrations', 'tenant_id'),
            ('tenants', 'tenant_id'),
            ('audit_logs', 'tenant_id'),
            ('mcp_query_audits', 'tenant_id'),
            ('static_policies', 'tenant_id'),
            ('dynamic_policies', 'tenant_id'),
            ('agent_audit_logs', 'client_id'),
            ('service_identities', 'tenant_id'),
            ('execution_history', 'tenant_id'),
            ('policy_evaluations', 'tenant_id')
        ) AS x(t, c)
    LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = rec.tname)
           AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = rec.tname AND column_name = 'org_id')
           AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = rec.tname AND column_name = rec.col) THEN
            EXECUTE format(
                'SELECT COUNT(*) FROM %I WHERE org_id = %L AND %I LIKE %L ESCAPE %L',
                rec.tname, 'community-saas', rec.col, 'cs\_%', '\'
            ) INTO remaining;
            RAISE NOTICE 'Migration 100 verify: %.org_id=''community-saas'' for cs_* %=% rows', rec.tname, rec.col, remaining;
        END IF;
    END LOOP;
END $$;

DO $$
BEGIN
    RAISE NOTICE 'Migration 100 complete — Community-SaaS cs_* org_id remap (idempotent re-run of 094 Pass-1)';
END $$;
