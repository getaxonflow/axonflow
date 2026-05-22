-- Migration 100 (down): restore org_id='community-saas' for cs_* cohort
-- Date: 2026-05-20
-- Context: Reverses 100_v9_phase6_csaas_org_id_remap.sql
--
-- Restores the shared constant on cs_* customer rows. Cohort selector: rows
-- whose tenant_id (or client_id) starts with 'cs_' AND whose org_id equals
-- that same identifier (i.e. the per-customer remap that 100 set or 094 had
-- already set is the only thing reverted; rows that never had the constant
-- are not touched).
--
-- IMPORTANT — 094 + 100 cohort symmetry: the SELECTOR (`org_id = <prefix-col>
-- AND <prefix-col> LIKE 'cs_%'`) cannot distinguish rows touched by 094 from
-- rows touched by 100. They write the SAME value (per-customer cs_<uuid>),
-- so running this _down alone reverts the FULL cs_* cohort — including
-- rows that 094 originally remapped. This is equivalent to running
-- 094_down + 100_down.
--
-- If the operator only wants to revert drift that landed between 094 and the
-- code-deploy that stopped writing the shared constant, there is no audit
-- column distinguishing the two cohorts; partial rollback is not possible
-- without an explicit before/after marker (which would need to be added in
-- a future migration).
--
-- Operational interpretation: this _down is appropriate when the full v9
-- cs_* remap work needs to be unwound on a stack — same blast radius as
-- 094_down. For a per-row rollback, use a one-off UPDATE against the
-- specific tenant_ids of interest, not this migration.

DO $$
DECLARE
    rec RECORD;
    rows_updated INTEGER;
BEGIN
    FOR rec IN
        SELECT t AS tname, c AS col FROM (VALUES
            ('community_saas_registrations', 'client_id'),
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
                'UPDATE %I SET org_id = %L WHERE org_id = %I AND %I LIKE %L ESCAPE %L',
                rec.tname, 'community-saas', rec.col, rec.col, 'cs\_%', '\'
            );
            GET DIAGNOSTICS rows_updated = ROW_COUNT;
            RAISE NOTICE 'Migration 100 (down): %.org_id restored to ''community-saas'' on % cs_* rows', rec.tname, rows_updated;
        END IF;
    END LOOP;
END $$;

DO $$
BEGIN
    RAISE NOTICE 'Migration 100 (down) complete — cs_* org_id remap reversed for drift cohort';
END $$;
