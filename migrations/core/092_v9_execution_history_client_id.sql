-- Migration 092: v9 execution_history client_id backfill + index
-- Date: 2026-05-19
--
-- Verified state (migrations/core/042 + 049, read 2026-05-19):
--   execution_history.tenant_id  VARCHAR(255)
--   execution_history.org_id     VARCHAR(255)
--   execution_history.client_id  VARCHAR(255)   ← already present since 042
--   execution_history.tenant_id  FK to organizations(org_id) WAS dropped in
--                                  migration 049. The FK contradiction flagged
--                                  by earlier identity design drafts is
--                                  therefore already resolved in current code
--                                  — no further FK work pending.
--
-- What this migration does:
--   (1) Backfill client_id from tenant_id where client_id is empty —
--       protects historical rows written before the SDK populated
--       Client.ID explicitly.
--   (2) Add (org_id, client_id, started_at) composite index for v9 hot-
--       path lookups.
--
-- Idempotency: WHERE-empty UPDATE + CREATE INDEX IF NOT EXISTS.
-- Rollback: paired _down.sql drops the index.
--
-- Depends on: 042_unified_execution_history, 049_execution_history_drop_tenant_fk

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'execution_history') THEN
        UPDATE execution_history
            SET client_id = tenant_id
            WHERE (client_id IS NULL OR client_id = '')
              AND tenant_id IS NOT NULL
              AND tenant_id <> '';

        CREATE INDEX IF NOT EXISTS idx_execution_history_org_client_time
            ON execution_history(org_id, client_id, started_at DESC);

        -- Document the v9 semantic on the existing column.
        EXECUTE 'COMMENT ON COLUMN execution_history.client_id IS ''Credential identity column. Predates the v9 migration; backfilled by 092 for rows with empty client_id. tenant_id remains as a deprecated alias.''';

        RAISE NOTICE 'Migration 092: execution_history client_id backfill + composite index applied';
    ELSE
        RAISE NOTICE 'Migration 092: execution_history missing — skipping';
    END IF;
END $$;

DO $$
BEGIN
    RAISE NOTICE 'Migration 092 complete — v9 execution_history additive layer';
END $$;
