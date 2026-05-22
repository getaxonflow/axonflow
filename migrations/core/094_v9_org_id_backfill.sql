-- Migration 094: v9 org_id backfill across customer-data tables
-- Date: 2026-05-19
--
-- Two-pass backfill strategy for the v9 identity migration:
--
--   Pass 1 (Community-SaaS rows):
--     Rows whose tenant_id (or client_id) starts with 'cs_' get
--     org_id = the cs_<uuid> value itself — collapsing the shared
--     org_id='community-saas' constant into per-customer identities.
--
--   Pass 2 (Self-hosted / in-VPC rows):
--     Rows whose tenant_id does NOT match the 'cs_' prefix get
--     org_id from the per-deployment session variable
--     `app.deployment_org_id`. The operator/runner sets this from the
--     ORG_ID environment variable before invoking the migration; falls
--     back to 'local-dev-org' if unset (matching v9 self-hosted default).
--
-- Pass 1 runs FIRST so that any row matching cs_* gets the per-customer
-- value; Pass 2's WHERE clause excludes those rows by requiring
-- (org_id IS NULL OR org_id = '' OR org_id = 'community-saas') AFTER
-- Pass 1 has run.
--
-- Idempotency: Every UPDATE has WHERE-empty/sentinel guards. Re-running
-- after a successful first pass is a no-op (the WHERE filters out rows
-- that already have correct values). The session-var helper is also
-- idempotent: set_config writes the value if needed but doesn't fail.
--
-- Rollback: paired _down.sql restores org_id='community-saas' on
-- ex-cs_* rows and clears the deployment-org backfill on others. This
-- restores schema + row state to byte-equal-pre-094 for the cohorts the
-- forward migration touched.
--
-- Safety:
--   - No write to community_saas_telemetry_events / prod-checkpoint-* DDB
--     (those are SoX-classified, scrubbed via dedicated workflows).
--   - No NOT NULL constraints added.
--   - No FORCE RLS.
--   - Read-only verification report emitted via RAISE NOTICE.
--
-- Depends on: 088_v9_credential_client_id (client_id columns must exist
--             before we can rely on the cs_ prefix check below),
--             059_runtime_tables_to_migrations (audit_logs.org_id),
--             061_org_tenant_identity (mcp_query_audits.org_id),
--             011_audit_logs (agent_audit_logs.org_id),
--             010_policy_tables (static_policies.org_id),
--             068_community_saas_registrations,
--             062_tenants_table

-- ============================================================================
-- Session-var precondition
-- ============================================================================
-- The agent's run.go propagates ORG_ID env into app.deployment_org_id
-- BEFORE invoking the migration runner. If the GUC is unset OR still has
-- the 'local-dev-org' default AND any non-cs_* row with empty org_id
-- exists in the backfill targets, FAIL LOUDLY — silently stamping every
-- historical audit row with 'local-dev-org' on a real deployment is
-- forward-only and unrecoverable. Self-healing default ONLY kicks in
-- when there's nothing for Pass-2 to backfill (clean install).
DO $$
DECLARE
    deployment_org TEXT;
    deployment_kind TEXT;
    has_non_csaas_empty BOOLEAN := FALSE;
    rec RECORD;
    cnt INTEGER;
BEGIN
    -- current_setting(name, missing_ok=true) returns NULL if unset
    deployment_org := current_setting('app.deployment_org_id', true);
    -- app.deployment_kind is set by the agent's setMigrationSessionVars from
    -- the DEPLOYMENT_KIND env var. Lets us distinguish a legitimate
    -- dev/community-mode 'local-dev-org' default from an operator who
    -- deployed to a real stack and forgot ORG_ID (which collapses to the
    -- same 'local-dev-org' value via getDeploymentOrgID's fallback).
    -- Treated as 'dev' when unset so the precondition behaves identically
    -- for any caller that doesn't propagate the kind GUC.
    deployment_kind := current_setting('app.deployment_kind', true);
    IF deployment_kind IS NULL OR deployment_kind = '' THEN
        deployment_kind := 'dev';
    END IF;

    -- Detect any non-cs_* row with empty org_id across the Pass-2 targets.
    -- These are the rows Pass-2 would silently stamp with the GUC value.
    FOR rec IN
        SELECT t AS tname, has_tenant AS has_tenant
        FROM (VALUES
            ('audit_logs', TRUE),
            ('agent_audit_logs', FALSE),
            ('mcp_query_audits', TRUE),
            ('llm_call_audits', FALSE),
            ('static_policies', TRUE),
            ('dynamic_policies', TRUE),
            ('policy_evaluations', TRUE),
            ('service_identities', TRUE),
            ('execution_history', TRUE)
        ) AS x(t, has_tenant)
    LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = rec.tname)
           AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = rec.tname AND column_name = 'org_id') THEN
            IF rec.has_tenant
               AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = rec.tname AND column_name = 'tenant_id') THEN
                EXECUTE format(
                    'SELECT COUNT(*) FROM %I WHERE (org_id IS NULL OR org_id = '''') AND (tenant_id IS NULL OR tenant_id NOT LIKE ''cs\_%%'' ESCAPE ''\'')',
                    rec.tname
                ) INTO cnt;
            ELSE
                EXECUTE format(
                    'SELECT COUNT(*) FROM %I WHERE org_id IS NULL OR org_id = ''''',
                    rec.tname
                ) INTO cnt;
            END IF;
            IF cnt > 0 THEN
                has_non_csaas_empty := TRUE;
                EXIT;
            END IF;
        END IF;
    END LOOP;

    -- Fail loud ONLY when the GUC is literally unset/empty AND there are
    -- rows for Pass-2 to backfill. This catches the regression case where
    -- run.go's setMigrationSessionVars helper got removed/skipped — the
    -- agent would then propagate nothing, the GUC would be NULL, and
    -- Pass-2 would silently stamp historical empty-org_id rows with
    -- 'local-dev-org' via the existing fallback below. We accept the
    -- 'local-dev-org' literal as a legitimate dev/community-mode default
    -- (docker-compose's docker-compose.yml + community-mode ship with
    -- ORG_ID unset → getDeploymentOrgID() returns 'local-dev-org' →
    -- setMigrationSessionVars sets the GUC to that value). Distinguishing
    -- dev-default from prod-forgot-ORG_ID requires a signal we don't have
    -- at SQL layer; operators who set ORG_ID in prod will see their value
    -- flow through, operators who don't will get the same behavior as
    -- pre-PR (no regression).
    IF (deployment_org IS NULL OR deployment_org = '') AND has_non_csaas_empty THEN
        RAISE EXCEPTION 'Migration 094 requires app.deployment_org_id set; ORG_ID env not propagated from agent to migration runner (run.go must SELECT set_config(''app.deployment_org_id'', $ORG_ID, false) before migrations execute). Refusing to run Pass-2 backfill — the fallback below would otherwise stamp historical empty-org_id rows with the ''local-dev-org'' default, which is forward-only and unrecoverable on a real deployment.';
    END IF;

    -- When DEPLOYMENT_KIND=production AND the org GUC fell through to
    -- 'local-dev-org', this is unambiguously the prod-forgot-ORG_ID
    -- regression — the agent's getDeploymentOrgID() returned the dev
    -- sentinel because ORG_ID env was unset, but the CFN template told us
    -- this is production.
    --
    -- We deliberately do NOT gate on `has_non_csaas_empty` here: fresh
    -- prod installs have no historical empty-org_id rows, but Pass-1 PREP
    -- further down seeds organizations.org_id =
    -- 'local-dev-org' and every subsequent write to audit_logs /
    -- agent_audit_logs / mcp_query_audits / policy_evaluations / etc.
    -- accrues under that sentinel. Fresh-install + prod-forgot is exactly
    -- the same forward-only poison as historical + prod-forgot, just
    -- prospective rather than retrospective. Fail loud regardless.
    --
    -- The first gate keeps has_non_csaas_empty to match the existing
    -- WARNING shape but does not cover the fresh-install + empty-deployment_org
    -- case on a production stack.
    --
    -- Second gate: also cover the helper-skipped + has_non_csaas_empty=FALSE
    -- case where deployment_org is NULL/'' on a prod stack. Defense-in-
    -- depth: the first branch above catches helper-skipped + history;
    -- this branch catches helper-skipped + fresh + production. There is
    -- no legitimate scenario where a production stack has either NULL
    -- or 'local-dev-org' as deployment_org.
    IF deployment_kind = 'production'
       AND (deployment_org IS NULL OR deployment_org = '' OR deployment_org = 'local-dev-org') THEN
        RAISE EXCEPTION 'Migration 094 prod-safety abort: app.deployment_kind=production but app.deployment_org_id=% (no valid deployment identity). Either ORG_ID env is unset on a production stack (getDeploymentOrgID falls through to ''local-dev-org'') or run.go skipped setMigrationSessionVars entirely (GUC unset). Migration would seed organizations(org_id=''local-dev-org'') and (on stacks with historical empty-org_id rows) stamp 9 audit tables with the dev sentinel; either case is forward-only and unrecoverable. Set ORG_ID env on the agent task definition to your real customer/account identifier (matches CFN OrganizationID — NOT the literal string ''local-dev-org'', which is the dev sentinel), redeploy, then re-run migrations.', COALESCE(deployment_org, '<NULL>');
    END IF;

    -- Soft-warn when GUC is the dev-default literal AND we have Pass-2 work to
    -- do — operators running migration 094 against a real deployment without
    -- ORG_ID set get a paper trail in pg logs. Not a hard EXCEPTION on the
    -- DEPLOYMENT_KIND=dev path because legitimate community-mode
    -- docker-compose runs use 'local-dev-org' (CI smoke tests broke when
    -- this was an EXCEPTION; the precondition was narrowed to community-mode
    -- only). The DEPLOYMENT_KIND=production case is now caught by the
    -- prod-safety branch above.
    IF deployment_org = 'local-dev-org' AND has_non_csaas_empty AND deployment_kind <> 'production' THEN
        RAISE WARNING 'Migration 094: app.deployment_org_id=local-dev-org (deployment default), app.deployment_kind=% AND Pass-2 has non-cs_* empty-org_id rows to backfill. If this is a real deployment, set ORG_ID env + DEPLOYMENT_KIND=production BEFORE re-running — the backfill is forward-only and unrecoverable. If this is community-mode / docker-compose / CI, no action needed.', deployment_kind;
    END IF;

    IF deployment_org IS NULL OR deployment_org = '' THEN
        PERFORM set_config('app.deployment_org_id', 'local-dev-org', false);
        RAISE NOTICE 'Migration 094: app.deployment_org_id unset — defaulted to local-dev-org (no Pass-2 targets present)';
    ELSE
        RAISE NOTICE 'Migration 094: app.deployment_org_id=% (caller-supplied)', deployment_org;
    END IF;
END $$;

-- ============================================================================
-- PASS 1 PREP: seed organizations rows for every cs_* identity in any source
-- ============================================================================
-- The tenants table has FK fk_tenants_org → organizations(org_id) (migration
-- 062). For Pass-1B to set tenants.org_id = 'cs_<uuid>', a matching row
-- MUST exist in organizations.
--
-- Sources of cs_* identifiers in this codebase (verified on staging snapshot
-- 2026-05-19):
--   - community_saas_registrations.tenant_id (most authoritative)
--   - tenants.tenant_id (may diverge from registrations — some staging tenants
--     are auto-registered before/without a paired registrations row)
--   - other tables (audit_logs etc.) — values copied from one of the above,
--     so transitively covered
--
-- We seed organizations from UNION ALL of (registrations, tenants).
-- ON CONFLICT DO NOTHING handles overlap deterministically.
--
-- tier='Community' + max_nodes=999999 mirrors the operational reality of
-- community-saas customers (no per-tenant licensing).
DO $$
DECLARE
    inserted_csaas INTEGER := 0;
    inserted_tenants INTEGER := 0;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'organizations') THEN
        RAISE NOTICE 'Migration 094 Pass-1 PREP: organizations missing — skipping';
        RETURN;
    END IF;

    -- Source 1: community_saas_registrations
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'community_saas_registrations') THEN
        INSERT INTO organizations (org_id, name, tier, max_nodes, license_key)
            SELECT DISTINCT tenant_id, COALESCE(label, tenant_id), 'Community', 999999, ''
            FROM community_saas_registrations
            WHERE tenant_id LIKE 'cs\_%' ESCAPE '\'
        ON CONFLICT (org_id) DO NOTHING;
        GET DIAGNOSTICS inserted_csaas = ROW_COUNT;
    END IF;

    -- Source 2: tenants table (may have rows not in registrations — staging-snapshot
    -- evidence 2026-05-19: 725 registrations vs 710 tenants; not 1:1)
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tenants') THEN
        INSERT INTO organizations (org_id, name, tier, max_nodes, license_key)
            SELECT DISTINCT tenant_id, COALESCE(name, tenant_id), 'Community', 999999, ''
            FROM tenants
            WHERE tenant_id LIKE 'cs\_%' ESCAPE '\'
        ON CONFLICT (org_id) DO NOTHING;
        GET DIAGNOSTICS inserted_tenants = ROW_COUNT;
    END IF;

    RAISE NOTICE 'Migration 094 Pass-1 PREP: % + % organizations rows inserted for cs_* identities (registrations + tenants additional)', inserted_csaas, inserted_tenants;
END $$;

-- Also seed an organizations row for the deployment org so Pass-2 self-hosted
-- backfill (which writes that value into tables FK-bound to organizations)
-- doesn't violate FK either. This only inserts if missing — idempotent.
DO $$
DECLARE
    deployment_org TEXT;
    inserted INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'organizations') THEN
        deployment_org := current_setting('app.deployment_org_id', true);
        IF deployment_org IS NULL OR deployment_org = '' THEN
            deployment_org := 'local-dev-org';
        END IF;
        INSERT INTO organizations (org_id, name, tier, max_nodes, license_key)
            VALUES (deployment_org, deployment_org, 'Community', 2, '')
        ON CONFLICT (org_id) DO NOTHING;
        GET DIAGNOSTICS inserted = ROW_COUNT;
        RAISE NOTICE 'Migration 094 Pass-1 PREP: deployment org=% organizations row ensured (% new)', deployment_org, inserted;
    END IF;
END $$;

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
        RAISE NOTICE 'Migration 094 Pass-1A: community_saas_registrations org_id remapped on % cs_* rows', rows_updated;
    ELSE
        RAISE NOTICE 'Migration 094 Pass-1A: community_saas_registrations or client_id column missing — skipping';
    END IF;
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
        RAISE NOTICE 'Migration 094 Pass-1B: tenants org_id remapped on % cs_* rows', rows_updated;
    ELSE
        RAISE NOTICE 'Migration 094 Pass-1B: tenants missing — skipping';
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
        RAISE NOTICE 'Migration 094 Pass-1C: audit_logs org_id remapped on % cs_* rows', rows_updated;
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
        RAISE NOTICE 'Migration 094 Pass-1D: mcp_query_audits org_id remapped on % cs_* rows', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- PASS 1E: static_policies — set org_id from tenant_id for cs_* rows
-- ============================================================================
-- Skip the 'global' sentinel rows entirely — they're system-wide and have no
-- per-customer org_id.
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
        RAISE NOTICE 'Migration 094 Pass-1E: static_policies org_id remapped on % cs_* rows', rows_updated;
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
        RAISE NOTICE 'Migration 094 Pass-1F: dynamic_policies org_id remapped on % cs_* rows', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- PASS 1G: agent_audit_logs — no tenant_id column, so backfill from session var
-- on cs_* client_id rows
-- ============================================================================
DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_audit_logs') THEN
        UPDATE agent_audit_logs
            SET org_id = client_id
            WHERE (org_id IS NULL OR org_id = '' OR org_id = 'community-saas')
              AND client_id LIKE 'cs\_%' ESCAPE '\';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 Pass-1G: agent_audit_logs org_id remapped on % cs_* rows', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- PASS 1I: service_identities — backfill org_id from tenant_id for cs_* rows
-- ============================================================================
-- service_identities has tenant_id + org_id (nullable). v9 model: org_id is
-- the customer/account boundary; for cs_* services it equals tenant_id.
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
        RAISE NOTICE 'Migration 094 Pass-1I: service_identities org_id remapped on % cs_* rows', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- PASS 1J: execution_history — backfill org_id from tenant_id for cs_* rows
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
        RAISE NOTICE 'Migration 094 Pass-1J: execution_history org_id remapped on % cs_* rows', rows_updated;
    END IF;
END $$;

-- ============================================================================
-- PASS 2: Self-hosted / in-VPC backfill from app.deployment_org_id
-- ============================================================================
-- Pass 1 has converted every cs_* row. Anything still empty is
-- self-hosted or in-VPC — backfill from the deployment session var.
-- The session var was set at the top of this migration (default
-- 'local-dev-org' if unset).

DO $$
DECLARE
    deployment_org TEXT;
    rows_updated INTEGER;
BEGIN
    deployment_org := current_setting('app.deployment_org_id', true);
    IF deployment_org IS NULL OR deployment_org = '' THEN
        deployment_org := 'local-dev-org';
    END IF;

    -- audit_logs
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_logs') THEN
        UPDATE audit_logs
            SET org_id = deployment_org
            WHERE (org_id IS NULL OR org_id = '');
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 Pass-2: audit_logs org_id=% set on % rows', deployment_org, rows_updated;
    END IF;

    -- agent_audit_logs
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_audit_logs') THEN
        UPDATE agent_audit_logs
            SET org_id = deployment_org
            WHERE (org_id IS NULL OR org_id = '');
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 Pass-2: agent_audit_logs org_id=% set on % rows', deployment_org, rows_updated;
    END IF;

    -- mcp_query_audits
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mcp_query_audits') THEN
        UPDATE mcp_query_audits
            SET org_id = deployment_org
            WHERE (org_id IS NULL OR org_id = '');
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 Pass-2: mcp_query_audits org_id=% set on % rows', deployment_org, rows_updated;
    END IF;

    -- static_policies (skip 'global' sentinel — those are system-wide)
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'static_policies') THEN
        UPDATE static_policies
            SET org_id = deployment_org
            WHERE (org_id IS NULL OR org_id = '')
              AND tenant_id <> 'global';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 Pass-2: static_policies org_id=% set on % rows', deployment_org, rows_updated;
    END IF;

    -- dynamic_policies (same)
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'dynamic_policies') THEN
        UPDATE dynamic_policies
            SET org_id = deployment_org
            WHERE (org_id IS NULL OR org_id = '')
              AND tenant_id <> 'global';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 Pass-2: dynamic_policies org_id=% set on % rows', deployment_org, rows_updated;
    END IF;

    -- llm_call_audits (org_id added in 089; no tenant_id to derive cs_* from,
    -- so all empty rows get the deployment org)
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'llm_call_audits')
       AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'llm_call_audits' AND column_name = 'org_id') THEN
        UPDATE llm_call_audits
            SET org_id = deployment_org
            WHERE (org_id IS NULL OR org_id = '');
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 Pass-2: llm_call_audits org_id=% set on % rows', deployment_org, rows_updated;
    END IF;

    -- service_identities (nullable org_id since 016)
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'service_identities') THEN
        UPDATE service_identities
            SET org_id = deployment_org
            WHERE (org_id IS NULL OR org_id = '');
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 Pass-2: service_identities org_id=% set on % rows', deployment_org, rows_updated;
    END IF;

    -- execution_history (nullable org_id since 042)
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'execution_history') THEN
        UPDATE execution_history
            SET org_id = deployment_org
            WHERE (org_id IS NULL OR org_id = '');
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 Pass-2: execution_history org_id=% set on % rows', deployment_org, rows_updated;
    END IF;

    -- policy_evaluations.org_id added in 090
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'policy_evaluations')
       AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'policy_evaluations' AND column_name = 'org_id') THEN
        -- Pass 1 equivalent: cs_* rows
        UPDATE policy_evaluations
            SET org_id = tenant_id
            WHERE (org_id IS NULL OR org_id = '' OR org_id = 'community-saas')
              AND tenant_id LIKE 'cs\_%' ESCAPE '\';
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 Pass-1H (deferred): policy_evaluations org_id remapped on % cs_* rows', rows_updated;

        -- Pass 2 equivalent: self-hosted
        UPDATE policy_evaluations
            SET org_id = deployment_org
            WHERE (org_id IS NULL OR org_id = '');
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 Pass-2: policy_evaluations org_id=% set on % rows', deployment_org, rows_updated;
    END IF;
END $$;

-- ============================================================================
-- Verification report
-- ============================================================================
-- Emit a final counts-by-table summary of remaining empty-org_id rows.
-- Should be 0 for every table that participates in customer-data RLS once
-- the matching write-path fix lands. Non-zero counts indicate a write-path
-- bug that needs to be fixed before FORCE RLS is enabled.
DO $$
DECLARE
    rec RECORD;
    remaining INTEGER;
BEGIN
    FOR rec IN
        SELECT t AS tname FROM (VALUES
            ('audit_logs'),
            ('agent_audit_logs'),
            ('mcp_query_audits'),
            ('llm_call_audits'),
            ('static_policies'),
            ('dynamic_policies'),
            ('policy_evaluations'),
            ('tenants'),
            ('community_saas_registrations'),
            ('service_identities'),
            ('execution_history')
        ) AS x(t)
    LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = rec.tname)
           AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = rec.tname AND column_name = 'org_id') THEN
            EXECUTE format('SELECT COUNT(*) FROM %I WHERE org_id IS NULL OR org_id = '''' OR org_id = ''community-saas''', rec.tname)
                INTO remaining;
            RAISE NOTICE 'Migration 094 verify: %.% rows with empty/shared org_id = %', rec.tname, 'org_id', remaining;
        END IF;
    END LOOP;
END $$;

DO $$
BEGIN
    RAISE NOTICE 'Migration 094 complete — v9 org_id backfill';
END $$;
