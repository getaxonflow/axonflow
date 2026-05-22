-- Migration 101: FORCE ROW LEVEL SECURITY on customer-facing audit tables
-- Date: 2026-05-20
--
-- This is the SECOND FORCE ROW LEVEL SECURITY migration (the first landed in
-- 099). It targets customer-facing audit tables — the tables agent and
-- orchestrator handlers query on every customer request. The primary value
-- is surfacing handler RLS-context wiring gaps: any handler that reads/writes
-- these tables without calling WithOrgScope returns zero rows post-FORCE.
--
-- Tables in this batch:
--   1. mcp_query_audits     — MCP connector audit (writer: agent/audit_queue.go)
--   2. audit_retention_config — SEBI retention config (reader: orchestrator/sebi)
--   3. decision_chain       — EU AI Act decision tracing (writer: agent/decision_chain.go)
--
-- Tables DEFERRED to follow-up work:
--   - agent_audit_logs / orchestrator_audit_logs — current INSERT statements
--     don't include org_id column; rows would silently fail WITH CHECK post-FORCE.
--     Requires plumbing orgID through the audit pipeline (3+ INSERT call sites).
--   - llm_call_audits — same shape: INSERT in audit_queue.go + gateway_handlers.go
--     omits org_id today. Defer until INSERTs add the column.
--   - audit_logs — has the cross-org audit_cleanup worker (DELETE across tenants)
--     using the master role. Post-FORCE on audit_logs the worker would silently
--     delete zero rows. Defer until cross-org work moves to axonflow_platform_admin.
--
-- Non-breaking when AXONFLOW_DB_USE_APP_ROLE=false: with the agent + orchestrator
-- handler wraps that ship alongside, every read/write goes through WithOrgScope
-- which sets app.current_org_id BEFORE the SQL. The master connection then
-- satisfies the org_id RLS policies the same way an app-role connection would.

BEGIN;

-- ============================================================================
-- mcp_query_audits — enable RLS + add org_id policy + FORCE
-- ============================================================================
-- Table created in migration 040 (no RLS).
-- org_id added in 061; backfilled to client_id in 089.
-- The audit_queue.go INSERT already populates org_id from MCPQueryAuditEntry.OrgID
-- (line 567), so FORCE here doesn't require any column additions on the writer.
ALTER TABLE mcp_query_audits ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS mcp_query_audits_org_isolation ON mcp_query_audits;
CREATE POLICY mcp_query_audits_org_isolation ON mcp_query_audits
    FOR ALL
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));

COMMENT ON POLICY mcp_query_audits_org_isolation ON mcp_query_audits IS
    'Per-org row visibility. org_id column added by migration 061; '
    'INSERT path (agent/audit_queue.go LogMCPQueryAudit) populates it from MCPQueryAuditEntry.';

-- ============================================================================
-- audit_retention_config — already has RLS+policy from 026; just FORCE
-- ============================================================================
-- Migration 026 enabled RLS + created audit_retention_config_org_isolation policy.
-- Reads are exclusively in orchestrator/sebi/sebi_audit_export_service.go
-- (checkRetentionCompliance, getRetentionConfig). The sebi handler now wraps
-- each per-tenant call in WithOrgScope in the same PR.
ALTER TABLE audit_retention_config ENABLE ROW LEVEL SECURITY;

-- Re-assert defensively — 026 created the policy unconditionally, but a future
-- migration could drop it.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'audit_retention_config'
          AND policyname = 'audit_retention_config_org_isolation'
    ) THEN
        CREATE POLICY audit_retention_config_org_isolation ON audit_retention_config
            FOR ALL
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));
        RAISE NOTICE 'Re-created audit_retention_config_org_isolation (migration 026 had been rolled back?)';
    ELSE
        RAISE NOTICE 'audit_retention_config_org_isolation exists (idempotent skip)';
    END IF;
END
$$;

-- ============================================================================
-- decision_chain — already has RLS+policy from 025; just FORCE
-- ============================================================================
-- Migration 025 enabled RLS on decision_chain. org_id is NOT NULL (CREATE TABLE
-- constraint). Policy: USING (org_id = get_current_org_id()).
-- INSERT path (agent/decision_chain.go recordToDB) already populates org_id from
-- DecisionEntry.OrgID. The recordToDB function is wrapped in WithOrgScope by
-- the release shipping this migration — async worker uses entry.OrgID; sync
-- writes use the request's OrgID derived from auth.
ALTER TABLE decision_chain ENABLE ROW LEVEL SECURITY;

-- Re-assert defensively. 025 had a DROP-POLICY+CREATE-POLICY pattern; depending
-- on which 025 file ran (decision_chain vs hitl_oversight_queue), the policy
-- may need re-creation.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'decision_chain'
          AND policyname = 'decision_chain_org_isolation'
    ) THEN
        CREATE POLICY decision_chain_org_isolation ON decision_chain
            FOR ALL
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));
        RAISE NOTICE 'Created decision_chain_org_isolation';
    ELSE
        RAISE NOTICE 'decision_chain_org_isolation exists (idempotent skip)';
    END IF;
END
$$;

-- ============================================================================
-- The point of this migration: FORCE ROW LEVEL SECURITY
-- ============================================================================
ALTER TABLE mcp_query_audits       FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_retention_config FORCE ROW LEVEL SECURITY;
ALTER TABLE decision_chain         FORCE ROW LEVEL SECURITY;

-- ============================================================================
-- Smoke verification
-- ============================================================================
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT relname,
               relrowsecurity AS rls_enabled,
               relforcerowsecurity AS rls_forced
        FROM pg_class
        WHERE relname IN ('mcp_query_audits', 'audit_retention_config', 'decision_chain')
        ORDER BY relname
    LOOP
        IF NOT r.rls_enabled THEN
            RAISE EXCEPTION 'Migration 101 failed: RLS not enabled on %', r.relname;
        END IF;
        IF NOT r.rls_forced THEN
            RAISE EXCEPTION 'Migration 101 failed: FORCE RLS not active on %', r.relname;
        END IF;
        RAISE NOTICE 'Migration 101 verified: % (rls_enabled=%, rls_forced=%)',
                     r.relname, r.rls_enabled, r.rls_forced;
    END LOOP;

    -- Verify each table has at least one app.current_org_id-based policy.
    FOR r IN
        SELECT tablename, COUNT(*) AS policy_count
        FROM pg_policies
        WHERE tablename IN ('mcp_query_audits', 'audit_retention_config', 'decision_chain')
          AND qual LIKE '%app.current_org_id%'
        GROUP BY tablename
    LOOP
        IF r.policy_count < 1 THEN
            RAISE EXCEPTION 'Migration 101 failed: % has no app.current_org_id policy', r.tablename;
        END IF;
        RAISE NOTICE 'Migration 101 verified: % has % org_id-based policies',
                     r.tablename, r.policy_count;
    END LOOP;
END
$$;

COMMIT;
