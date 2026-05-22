-- Migration 089: v9 audit-table client_id verification + composite indexes
-- Date: 2026-05-19
--
-- Classification (credential class): audit_logs, mcp_query_audits,
-- llm_call_audits, agent_audit_logs.
--
-- Inventory finding (verified 2026-05-19 against migrations/core/):
--   audit_logs (059):          tenant_id + client_id both present; client_id
--                              already carries v9 credential semantic from
--                              req.Client.ID (platform/orchestrator/audit_logger.go:198).
--   mcp_query_audits (040):    tenant_id + client_id both present (NOT NULL).
--   llm_call_audits (020):     client_id present (NOT NULL); no tenant_id column.
--   agent_audit_logs (011):    client_id present (nullable); no tenant_id column.
--
-- So no new column is needed on any of these four. This migration:
--   (1) Backfills client_id from tenant_id ONLY where client_id is empty and
--       tenant_id has a value — covers historical rows from before the
--       writer started populating client_id.
--   (2) Adds the (org_id, client_id, timestamp/created_at) composite index
--       so the v9 hot-path read pattern (per-org-per-credential, latest-first)
--       is supported once FORCE RLS lands.
--
-- Idempotency: every WHERE-empty UPDATE + every CREATE INDEX IF NOT EXISTS.
-- Re-running this migration is a no-op.
--
-- Rollback: paired scripts/v9_rollback/089_rollback.sql drops the new indexes.
-- Backfilled data is left in place — it represents historical truth that
-- was already correct semantically (req.Client.ID == basic-auth credential).
--
-- Depends on: 011_audit_logs, 020_gateway_mode_audit, 040_mcp_query_audits,
--             059_runtime_tables_to_migrations, 061_org_tenant_identity

-- ============================================================================
-- audit_logs (059)
-- ============================================================================
-- audit_logs has been writing client_id and tenant_id since 059. For rows
-- where the writer set client_id NULL/'' (legacy path or partial writes),
-- backfill from tenant_id which is NOT NULL by schema.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_logs') THEN
        UPDATE audit_logs
            SET client_id = tenant_id
            WHERE (client_id IS NULL OR client_id = '')
              AND tenant_id IS NOT NULL
              AND tenant_id <> '';

        -- v9 hot-path read index. Existing audit_logs has separate indexes
        -- on tenant_id, org_id, timestamp, etc.; the composite supports the
        -- v9 query shape WHERE org_id=$1 AND client_id=$2 ORDER BY timestamp DESC.
        CREATE INDEX IF NOT EXISTS idx_audit_logs_org_client_time
            ON audit_logs(org_id, client_id, timestamp DESC);

        RAISE NOTICE 'Migration 089: audit_logs backfill + composite index applied';
    ELSE
        RAISE NOTICE 'Migration 089: audit_logs missing — skipping';
    END IF;
END $$;

-- ============================================================================
-- mcp_query_audits (040)
-- ============================================================================
-- mcp_query_audits has both columns NOT NULL since 040 + org_id added in 061.
-- Backfill any pre-061 rows whose client_id slipped in empty (defensive — the
-- column was NOT NULL from creation so this should be a no-op in practice).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'mcp_query_audits') THEN
        UPDATE mcp_query_audits
            SET client_id = tenant_id
            WHERE (client_id IS NULL OR client_id = '')
              AND tenant_id IS NOT NULL
              AND tenant_id <> '';

        CREATE INDEX IF NOT EXISTS idx_mcp_query_audits_org_client_time
            ON mcp_query_audits(org_id, client_id, created_at DESC);

        RAISE NOTICE 'Migration 089: mcp_query_audits backfill + composite index applied';
    ELSE
        RAISE NOTICE 'Migration 089: mcp_query_audits missing — skipping';
    END IF;
END $$;

-- ============================================================================
-- llm_call_audits (020)
-- ============================================================================
-- llm_call_audits has client_id NOT NULL but no tenant_id column — it was
-- born v9-shaped in the credential dimension. It has no org_id today.
-- Add org_id (additive, nullable) so a later backfill migration can populate
-- it from audit_logs/mcp_query_audits row joins, and add the composite index.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'llm_call_audits') THEN
        ALTER TABLE llm_call_audits
            ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);

        -- No backfill from tenant_id (column does not exist). Migration 094
        -- will populate org_id from the per-deployment session var fallback
        -- for any rows still empty after the write-path fix lands.

        CREATE INDEX IF NOT EXISTS idx_llm_call_audits_org_client_time
            ON llm_call_audits(org_id, client_id, created_at DESC);

        RAISE NOTICE 'Migration 089: llm_call_audits.org_id added + composite index applied';
    ELSE
        RAISE NOTICE 'Migration 089: llm_call_audits missing — skipping';
    END IF;
END $$;

-- ============================================================================
-- agent_audit_logs (011)
-- ============================================================================
-- agent_audit_logs has client_id (nullable) but no tenant_id column. The
-- column was always v9-credential-shaped. Add the org_id+client_id+timestamp
-- composite index; org_id population is handled in 094.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_audit_logs') THEN
        CREATE INDEX IF NOT EXISTS idx_agent_audit_logs_org_client_time
            ON agent_audit_logs(org_id, client_id, timestamp DESC);

        RAISE NOTICE 'Migration 089: agent_audit_logs composite index applied';
    ELSE
        RAISE NOTICE 'Migration 089: agent_audit_logs missing — skipping';
    END IF;
END $$;

-- ============================================================================
-- Column documentation
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
END $$;

DO $$
BEGIN
    RAISE NOTICE 'Migration 089 complete — v9 audit-table client_id verification + composite indexes';
END $$;
