-- Down migration for 089: drop the v9 audit-table composite indexes + the
-- additive org_id column on llm_call_audits.
-- Pairs with: 089_v9_audit_tables_client_id.sql
--
-- Backfilled client_id values in audit_logs / mcp_query_audits are left in
-- place. Those values are semantically correct (req.Client.ID), so the
-- byte-equal-pre-state guarantee scopes to schema, not historical data:
-- the migration writes only WHERE client_id was empty AND tenant_id was
-- populated, so for any row this migration touched, post-rollback client_id
-- ends up equal to tenant_id — the same effective value that production
-- code would have written had the request been re-replayed.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_audit_logs') THEN
        DROP INDEX IF EXISTS idx_agent_audit_logs_org_client_time;
        RAISE NOTICE 'Migration 089 DOWN: agent_audit_logs composite index dropped';
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'llm_call_audits') THEN
        DROP INDEX IF EXISTS idx_llm_call_audits_org_client_time;
        ALTER TABLE llm_call_audits DROP COLUMN IF EXISTS org_id;
        RAISE NOTICE 'Migration 089 DOWN: llm_call_audits.org_id + composite index dropped';
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mcp_query_audits') THEN
        DROP INDEX IF EXISTS idx_mcp_query_audits_org_client_time;
        -- Clear the v9 COMMENT added by the forward migration (the column
        -- pre-existed in 040 and had no COMMENT, so NULL restores baseline).
        EXECUTE 'COMMENT ON COLUMN mcp_query_audits.client_id IS NULL';
        RAISE NOTICE 'Migration 089 DOWN: mcp_query_audits composite index dropped + COMMENT cleared';
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_logs') THEN
        DROP INDEX IF EXISTS idx_audit_logs_org_client_time;
        -- Clear the v9 COMMENT added by the forward migration (the column
        -- pre-existed in 059 and had no COMMENT).
        EXECUTE 'COMMENT ON COLUMN audit_logs.client_id IS NULL';
        RAISE NOTICE 'Migration 089 DOWN: audit_logs composite index dropped + COMMENT cleared';
    END IF;
END $$;
