-- Migration 061: Add org_id to mcp_query_audits for org-level queries
-- Date: 2026-04-05
-- Context: Issue #1492 — Unified identity model (org_id + tenant_id)
--
-- Note: audit_logs org_id is handled by migration 059_runtime_tables_to_migrations.
-- This migration only covers mcp_query_audits which was not part of that migration.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mcp_query_audits') THEN
        ALTER TABLE mcp_query_audits ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);
        UPDATE mcp_query_audits SET org_id = tenant_id WHERE org_id IS NULL AND tenant_id IS NOT NULL AND tenant_id != '';
        CREATE INDEX IF NOT EXISTS idx_mcp_query_audits_org_id ON mcp_query_audits(org_id);
        RAISE NOTICE 'Migration 061: Added org_id to mcp_query_audits';
    ELSE
        RAISE NOTICE 'Migration 061: mcp_query_audits does not exist yet — skipping';
    END IF;
END $$;
