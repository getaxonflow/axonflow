-- Rollback Migration 061

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mcp_query_audits') THEN
        DROP INDEX IF EXISTS idx_mcp_query_audits_org_id;
        ALTER TABLE mcp_query_audits DROP COLUMN IF EXISTS org_id;
    END IF;
END $$;
