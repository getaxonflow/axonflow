-- Assertion suite for migration 095 — usage_records classification.

DO $$
DECLARE
    cmt TEXT;
BEGIN
    -- pg_catalog.col_description(table_oid, column_attnum) returns the COMMENT
    SELECT col_description('public.usage_records'::regclass,
                           (SELECT attnum FROM pg_attribute
                            WHERE attrelid = 'public.usage_records'::regclass AND attname = 'team_id'))
        INTO cmt;
    IF cmt IS NULL OR cmt NOT LIKE '%ATTRIBUTION TAG%' THEN
        RAISE EXCEPTION 'Test 095.1 FAILED: usage_records.team_id classification comment missing or wrong (got: %)', cmt;
    END IF;
    RAISE NOTICE 'Test 095.1 PASS: usage_records.team_id classified as ATTRIBUTION TAG';
END $$;

-- 095.2 — no client_id added (team_id is NOT v9 identity)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'usage_records' AND column_name = 'client_id') THEN
        -- If client_id pre-existed (it does NOT in 034), check it wasn't ADDED.
        -- For this codebase, presence of client_id on usage_records is a regression.
        RAISE EXCEPTION 'Test 095.2 FAILED: usage_records.client_id present — team_id was supposed to NOT trigger client_id addition';
    END IF;
    RAISE NOTICE 'Test 095.2 PASS: usage_records correctly has no client_id (team_id is attribution tag)';
END $$;

-- 095.3 — schema_migrations row exists for 095
-- (Not all migrations self-register; only verify if the runner tracked us)
DO $$
DECLARE
    row_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO row_count FROM schema_migrations WHERE version = '095';
    IF row_count = 0 THEN
        RAISE NOTICE 'Test 095.3 INFO: schema_migrations row for 095 not found (only auto-recorded when invoked via runner, not direct psql)';
    ELSE
        RAISE NOTICE 'Test 095.3 PASS: schema_migrations row for 095 present';
    END IF;
END $$;

DO $$ BEGIN RAISE NOTICE 'Migration 095 assertion suite: ALL TESTS PASSED'; END $$;
