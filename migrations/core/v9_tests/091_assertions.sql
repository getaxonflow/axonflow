-- Assertion suite for migration 091 — v9 service-identity client_id.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'service_identities' AND column_name = 'client_id') THEN
        RAISE EXCEPTION 'Test 091.1 FAILED: service_identities.client_id missing';
    END IF;
    RAISE NOTICE 'Test 091.1 PASS: service_identities.client_id present';
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_service_identities_client_id') THEN
        RAISE EXCEPTION 'Test 091.2a FAILED: idx_service_identities_client_id missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_service_identities_org_client') THEN
        RAISE EXCEPTION 'Test 091.2b FAILED: idx_service_identities_org_client missing';
    END IF;
    RAISE NOTICE 'Test 091.2 PASS: service_identities indexes present';
END $$;

-- Backfill correctness
DO $$
DECLARE
    gaps INTEGER;
BEGIN
    SELECT COUNT(*) INTO gaps
        FROM service_identities
        WHERE (client_id IS NULL OR client_id = '')
          AND tenant_id IS NOT NULL AND tenant_id <> '';
    IF gaps > 0 THEN
        RAISE EXCEPTION 'Test 091.3 FAILED: service_identities has % rows with empty client_id', gaps;
    END IF;
    RAISE NOTICE 'Test 091.3 PASS: service_identities backfilled';
END $$;

-- service_role_assignments: forward-compatible — should be absent today
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'service_role_assignments') THEN
        RAISE NOTICE 'Test 091.4 INFO: service_role_assignments exists — verify client_id was added';
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'service_role_assignments' AND column_name = 'client_id') THEN
            RAISE EXCEPTION 'Test 091.4 FAILED: service_role_assignments exists but lacks client_id';
        END IF;
    ELSE
        RAISE NOTICE 'Test 091.4 INFO: service_role_assignments absent (expected on current codebase)';
    END IF;
END $$;

DO $$ BEGIN RAISE NOTICE 'Migration 091 assertion suite: ALL TESTS PASSED'; END $$;
