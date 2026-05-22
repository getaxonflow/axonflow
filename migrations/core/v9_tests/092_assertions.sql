-- Assertion suite for migration 092 — v9 execution_history client_id.

-- 092.1 — pre-existing client_id column still present (must not have been replaced)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'execution_history' AND column_name = 'client_id') THEN
        RAISE EXCEPTION 'Test 092.1 FAILED: execution_history.client_id missing';
    END IF;
    RAISE NOTICE 'Test 092.1 PASS: execution_history.client_id present';
END $$;

-- 092.2 — composite index added
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_execution_history_org_client_time') THEN
        RAISE EXCEPTION 'Test 092.2 FAILED: idx_execution_history_org_client_time missing';
    END IF;
    RAISE NOTICE 'Test 092.2 PASS: composite index present';
END $$;

-- 092.3 — broken FK from 042 should be ABSENT (dropped by migration 049)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.table_constraints
               WHERE constraint_name = 'execution_history_tenant_id_fkey'
                 AND table_name = 'execution_history') THEN
        RAISE EXCEPTION 'Test 092.3 FAILED: execution_history_tenant_id_fkey unexpectedly present — migration 049 was supposed to drop it';
    END IF;
    RAISE NOTICE 'Test 092.3 PASS: execution_history_tenant_id_fkey absent (049 effective)';
END $$;

-- 092.4 — backfill correctness
DO $$
DECLARE
    gaps INTEGER;
BEGIN
    SELECT COUNT(*) INTO gaps
        FROM execution_history
        WHERE (client_id IS NULL OR client_id = '')
          AND tenant_id IS NOT NULL AND tenant_id <> '';
    IF gaps > 0 THEN
        RAISE EXCEPTION 'Test 092.4 FAILED: execution_history has % rows with empty client_id but populated tenant_id', gaps;
    END IF;
    RAISE NOTICE 'Test 092.4 PASS: execution_history backfilled';
END $$;

DO $$ BEGIN RAISE NOTICE 'Migration 092 assertion suite: ALL TESTS PASSED'; END $$;
