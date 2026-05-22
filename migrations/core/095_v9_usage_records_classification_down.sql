-- Down migration for 095: restore pre-095 COMMENT state on usage_records.
-- Pairs with: 095_v9_usage_records_classification.sql
--
-- Forward migration only wrote COMMENTs. Down clears them so pg_dump
-- output matches pre-095 byte-for-byte. Original migration 034 did not
-- set any COMMENT on usage_records.{team_id,org_id,tenant_id}, so NULL
-- is the correct restored state.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'usage_records') THEN
        EXECUTE 'COMMENT ON COLUMN usage_records.team_id IS NULL';
        EXECUTE 'COMMENT ON COLUMN usage_records.org_id IS NULL';
        EXECUTE 'COMMENT ON COLUMN usage_records.tenant_id IS NULL';
        RAISE NOTICE 'Migration 095 DOWN: usage_records comments cleared';
    END IF;
END $$;
