-- Assertion suite for migration 089 — v9 audit-table client_id verification.
-- Apply AFTER migration 089. RAISEs EXCEPTION on invariant violation.

-- 089.1 — composite indexes exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_audit_logs_org_client_time') THEN
        RAISE EXCEPTION 'Test 089.1a FAILED: idx_audit_logs_org_client_time missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_mcp_query_audits_org_client_time') THEN
        RAISE EXCEPTION 'Test 089.1b FAILED: idx_mcp_query_audits_org_client_time missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_llm_call_audits_org_client_time') THEN
        RAISE EXCEPTION 'Test 089.1c FAILED: idx_llm_call_audits_org_client_time missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_agent_audit_logs_org_client_time') THEN
        RAISE EXCEPTION 'Test 089.1d FAILED: idx_agent_audit_logs_org_client_time missing';
    END IF;
    RAISE NOTICE 'Test 089.1 PASS: all 089 composite indexes present';
END $$;

-- 089.2 — llm_call_audits.org_id column added
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'llm_call_audits' AND column_name = 'org_id') THEN
        RAISE EXCEPTION 'Test 089.2 FAILED: llm_call_audits.org_id missing';
    END IF;
    RAISE NOTICE 'Test 089.2 PASS: llm_call_audits.org_id present';
END $$;

-- 089.3 — pre-existing client_id columns NOT dropped (audit_logs, mcp_query_audits)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'audit_logs' AND column_name = 'client_id') THEN
        RAISE EXCEPTION 'Test 089.3a FAILED: audit_logs.client_id was dropped by 089 (should be preserved)';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'mcp_query_audits' AND column_name = 'client_id') THEN
        RAISE EXCEPTION 'Test 089.3b FAILED: mcp_query_audits.client_id was dropped by 089';
    END IF;
    RAISE NOTICE 'Test 089.3 PASS: pre-existing client_id columns preserved';
END $$;

-- 089.4 — backfill: no rows have empty client_id where tenant_id is populated
DO $$
DECLARE
    audit_gaps INTEGER;
    mcp_gaps   INTEGER;
BEGIN
    SELECT COUNT(*) INTO audit_gaps
        FROM audit_logs
        WHERE (client_id IS NULL OR client_id = '')
          AND tenant_id IS NOT NULL AND tenant_id <> '';
    IF audit_gaps > 0 THEN
        RAISE EXCEPTION 'Test 089.4a FAILED: audit_logs has % rows with empty client_id but populated tenant_id', audit_gaps;
    END IF;

    SELECT COUNT(*) INTO mcp_gaps
        FROM mcp_query_audits
        WHERE (client_id IS NULL OR client_id = '')
          AND tenant_id IS NOT NULL AND tenant_id <> '';
    IF mcp_gaps > 0 THEN
        RAISE EXCEPTION 'Test 089.4b FAILED: mcp_query_audits has % rows with empty client_id', mcp_gaps;
    END IF;

    RAISE NOTICE 'Test 089.4 PASS: audit-table client_id backfilled where derivable';
END $$;

DO $$ BEGIN RAISE NOTICE 'Migration 089 assertion suite: ALL TESTS PASSED'; END $$;
