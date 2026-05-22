-- Assertion suite for migration 090 — v9 policy tables client_id.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'static_policies' AND column_name = 'client_id') THEN
        RAISE EXCEPTION 'Test 090.1a FAILED: static_policies.client_id missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'dynamic_policies' AND column_name = 'client_id') THEN
        RAISE EXCEPTION 'Test 090.1b FAILED: dynamic_policies.client_id missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'policy_evaluations' AND column_name = 'client_id') THEN
        RAISE EXCEPTION 'Test 090.1c FAILED: policy_evaluations.client_id missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'policy_evaluations' AND column_name = 'org_id') THEN
        RAISE EXCEPTION 'Test 090.1d FAILED: policy_evaluations.org_id missing';
    END IF;
    RAISE NOTICE 'Test 090.1 PASS: policy-table client_id + org_id columns present';
END $$;

-- Indexes
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_static_policies_client') THEN
        RAISE EXCEPTION 'Test 090.2a FAILED: idx_static_policies_client missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_static_policies_org_client') THEN
        RAISE EXCEPTION 'Test 090.2b FAILED: idx_static_policies_org_client missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_dynamic_policies_client') THEN
        RAISE EXCEPTION 'Test 090.2c FAILED: idx_dynamic_policies_client missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_dynamic_policies_org_client') THEN
        RAISE EXCEPTION 'Test 090.2d FAILED: idx_dynamic_policies_org_client missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_policy_evaluations_client_time') THEN
        RAISE EXCEPTION 'Test 090.2e FAILED: idx_policy_evaluations_client_time missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_policy_evaluations_org_client_time') THEN
        RAISE EXCEPTION 'Test 090.2f FAILED: idx_policy_evaluations_org_client_time missing';
    END IF;
    RAISE NOTICE 'Test 090.2 PASS: all 090 policy indexes present';
END $$;

-- 'global' sentinel preserved verbatim (semantic preservation)
DO $$
DECLARE
    drifted INTEGER;
BEGIN
    SELECT COUNT(*) INTO drifted
        FROM static_policies
        WHERE tenant_id = 'global' AND (client_id <> 'global' AND client_id IS NOT NULL);
    IF drifted > 0 THEN
        RAISE EXCEPTION 'Test 090.3 FAILED: % static_policies rows with tenant_id=global have drifted client_id', drifted;
    END IF;
    RAISE NOTICE 'Test 090.3 PASS: global sentinel preserved on static_policies';
END $$;

-- Backfill correctness: every populated tenant_id has matching client_id
DO $$
DECLARE
    static_gaps  INTEGER;
    dynamic_gaps INTEGER;
    eval_gaps    INTEGER;
BEGIN
    SELECT COUNT(*) INTO static_gaps
        FROM static_policies
        WHERE (client_id IS NULL OR client_id = '')
          AND tenant_id IS NOT NULL AND tenant_id <> '';
    IF static_gaps > 0 THEN
        RAISE EXCEPTION 'Test 090.4a FAILED: static_policies has % rows with empty client_id', static_gaps;
    END IF;

    SELECT COUNT(*) INTO dynamic_gaps
        FROM dynamic_policies
        WHERE (client_id IS NULL OR client_id = '')
          AND tenant_id IS NOT NULL AND tenant_id <> '';
    IF dynamic_gaps > 0 THEN
        RAISE EXCEPTION 'Test 090.4b FAILED: dynamic_policies has % rows with empty client_id', dynamic_gaps;
    END IF;

    SELECT COUNT(*) INTO eval_gaps
        FROM policy_evaluations
        WHERE (client_id IS NULL OR client_id = '')
          AND tenant_id IS NOT NULL AND tenant_id <> '';
    IF eval_gaps > 0 THEN
        RAISE EXCEPTION 'Test 090.4c FAILED: policy_evaluations has % rows with empty client_id', eval_gaps;
    END IF;

    RAISE NOTICE 'Test 090.4 PASS: all policy tables backfilled where derivable';
END $$;

DO $$ BEGIN RAISE NOTICE 'Migration 090 assertion suite: ALL TESTS PASSED'; END $$;
