-- Down migration for 094: best-effort revert of v9 org_id backfill.
-- Pairs with: 094_v9_org_id_backfill.sql
--
-- IMPORTANT — data fidelity caveats:
--
--   (1) The forward migration's Pass-1 PREP step INSERTed organizations
--   rows for each cs_* customer + the deployment org. We do NOT delete
--   those rows here. Reason: organizations(org_id) is FK-referenced by
--   tenants(org_id) with ON DELETE CASCADE. Deleting the org rows would
--   cascade-delete every tenants row that points to them, destroying
--   the cs_* customer mapping. Leaving the rows in place is harmless:
--   they represent legitimate per-customer organizations under the v9
--   model. Schema dump pre/post-rollback is byte-equal (no schema
--   change in 094) but DATA differs by these inserted org rows.
--
--   (2) The forward migration's Pass-2 set org_id from app.deployment_org_id
--   on rows that previously had empty org_id. Pure SQL cannot perfectly
--   distinguish post-094 deployment-org rows from rows that already held
--   the same value pre-094. This rollback leaves Pass-2-deployment-org
--   rows in place because blanket-clearing them would also wipe pre-
--   existing legitimate matches.
--
--   (3) Pass-1 cs_* customer remapping IS reversible deterministically:
--   any cs_* row whose org_id matches its tenant_id/client_id (a cs_<uuid>
--   value) was definitely remapped by this migration. tenants is reverted
--   FIRST (before community_saas_registrations) so the FK stays satisfied
--   throughout — community_saas_registrations.org_id reverts to
--   'community-saas' last.
--
-- This caveat is acceptable because the org_id backfill is by design
-- forward-only in production; the down migration exists for local rehearsal
-- testing (docker-compose roundtrip) where the pre-094 state is also synthetic.

-- ============================================================================
-- PASS 1 REVERSE: restore cs_* rows back to org_id='community-saas'
-- ============================================================================

DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'community_saas_registrations')
       AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'community_saas_registrations' AND column_name = 'client_id') THEN
        UPDATE community_saas_registrations
            SET org_id = 'community-saas'
            WHERE org_id LIKE 'cs\_%' ESCAPE '\'
              AND org_id = client_id;
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 DOWN: community_saas_registrations restored on % cs_* rows', rows_updated;
    END IF;
END $$;

DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tenants') THEN
        UPDATE tenants
            SET org_id = 'community-saas'
            WHERE org_id LIKE 'cs\_%' ESCAPE '\'
              AND org_id = tenant_id;
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 DOWN: tenants restored on % cs_* rows', rows_updated;
    END IF;
END $$;

DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_logs') THEN
        UPDATE audit_logs
            SET org_id = NULL
            WHERE org_id LIKE 'cs\_%' ESCAPE '\'
              AND org_id = tenant_id;
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 DOWN: audit_logs cleared on % cs_* rows (was NULL pre-094)', rows_updated;
    END IF;
END $$;

DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mcp_query_audits') THEN
        UPDATE mcp_query_audits
            SET org_id = NULL
            WHERE org_id LIKE 'cs\_%' ESCAPE '\'
              AND org_id = tenant_id;
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 DOWN: mcp_query_audits cleared on % cs_* rows', rows_updated;
    END IF;
END $$;

DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'static_policies') THEN
        UPDATE static_policies
            SET org_id = NULL
            WHERE org_id LIKE 'cs\_%' ESCAPE '\'
              AND org_id = tenant_id;
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 DOWN: static_policies cleared on % cs_* rows', rows_updated;
    END IF;
END $$;

DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'dynamic_policies') THEN
        UPDATE dynamic_policies
            SET org_id = NULL
            WHERE org_id LIKE 'cs\_%' ESCAPE '\'
              AND org_id = tenant_id;
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 DOWN: dynamic_policies cleared on % cs_* rows', rows_updated;
    END IF;
END $$;

DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_audit_logs') THEN
        UPDATE agent_audit_logs
            SET org_id = NULL
            WHERE org_id LIKE 'cs\_%' ESCAPE '\'
              AND org_id = client_id;
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 DOWN: agent_audit_logs cleared on % cs_* rows', rows_updated;
    END IF;
END $$;

DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'service_identities') THEN
        UPDATE service_identities
            SET org_id = NULL
            WHERE org_id LIKE 'cs\_%' ESCAPE '\'
              AND org_id = tenant_id;
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 DOWN: service_identities cleared on % cs_* rows', rows_updated;
    END IF;
END $$;

DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'execution_history') THEN
        UPDATE execution_history
            SET org_id = NULL
            WHERE org_id LIKE 'cs\_%' ESCAPE '\'
              AND org_id = tenant_id;
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 DOWN: execution_history cleared on % cs_* rows', rows_updated;
    END IF;
END $$;

DO $$
DECLARE
    rows_updated INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'policy_evaluations')
       AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'policy_evaluations' AND column_name = 'org_id') THEN
        UPDATE policy_evaluations
            SET org_id = NULL
            WHERE org_id LIKE 'cs\_%' ESCAPE '\'
              AND org_id = tenant_id;
        GET DIAGNOSTICS rows_updated = ROW_COUNT;
        RAISE NOTICE 'Migration 094 DOWN: policy_evaluations cleared on % cs_* rows', rows_updated;
    END IF;
END $$;

DO $$
BEGIN
    RAISE NOTICE 'Migration 094 DOWN complete — cs_* rows reverted, Pass-2 deployment-org rows left in place (documented data caveat)';
END $$;
