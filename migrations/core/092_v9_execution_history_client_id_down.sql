-- Down migration for 092: drop execution_history v9 composite index.
-- Pairs with: 092_v9_execution_history_client_id.sql
--
-- The forward migration only added an index + ran a WHERE-empty backfill.
-- Dropping the index returns the schema to byte-equal pre-state. Backfilled
-- client_id rows are left in place — they mirror tenant_id and represent
-- the same effective value the SDK would have written.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'execution_history') THEN
        DROP INDEX IF EXISTS idx_execution_history_org_client_time;
        -- Clear the v9 COMMENT added by the forward migration (the column
        -- pre-existed in 042 and had no COMMENT).
        EXECUTE 'COMMENT ON COLUMN execution_history.client_id IS NULL';
        RAISE NOTICE 'Migration 092 DOWN: execution_history composite index dropped + COMMENT cleared';
    END IF;
END $$;
