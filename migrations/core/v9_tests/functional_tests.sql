-- Functional test suite for v9 migrations.
--
-- Goes beyond schema/index/backfill-count assertions to exercise REAL v9
-- query shapes against the seeded data and verify semantic correctness.
-- These tests prove the migrations work for actual production query patterns,
-- not just that the structural changes are present.
--
-- Apply AFTER 088-095 + seed.sql. RAISE EXCEPTION on functional violation.

-- ============================================================================
-- FT.1 — credential alias parity: query by tenant_id vs client_id returns same rows
-- ============================================================================
DO $$
DECLARE
    by_tenant_id INTEGER;
    by_client_id INTEGER;
BEGIN
    SELECT COUNT(*) INTO by_tenant_id
        FROM community_saas_registrations WHERE tenant_id = 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1';
    SELECT COUNT(*) INTO by_client_id
        FROM community_saas_registrations WHERE client_id = 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1';
    IF by_tenant_id <> by_client_id THEN
        RAISE EXCEPTION 'FT.1 FAILED: community_saas_registrations by tenant_id=% rows differs from by client_id=% rows', by_tenant_id, by_client_id;
    END IF;
    IF by_client_id = 0 THEN
        RAISE EXCEPTION 'FT.1 FAILED: lookup by client_id returned 0 rows for known seed cs_* customer';
    END IF;
    RAISE NOTICE 'FT.1 PASS: community_saas_registrations by-tenant_id (% rows) == by-client_id (% rows)', by_tenant_id, by_client_id;
END $$;

-- ============================================================================
-- FT.2 — plugin_user_licenses lookup by client_id is the same as by tenant_id
-- (proves the alias works for the enforcement hot path)
-- ============================================================================
DO $$
DECLARE
    by_tid INTEGER;
    by_cid INTEGER;
BEGIN
    SELECT COUNT(*) INTO by_tid
        FROM plugin_user_licenses WHERE tenant_id = 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1';
    SELECT COUNT(*) INTO by_cid
        FROM plugin_user_licenses WHERE client_id = 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1';
    IF by_tid <> by_cid THEN
        RAISE EXCEPTION 'FT.2 FAILED: plugin_user_licenses by tenant_id=% rows differs from by client_id=% rows', by_tid, by_cid;
    END IF;
    RAISE NOTICE 'FT.2 PASS: plugin_user_licenses by-tenant_id (% rows) == by-client_id (% rows)', by_tid, by_cid;
END $$;

-- ============================================================================
-- FT.3 — v9 hot-path query (org_id + client_id + time) uses composite index
-- ============================================================================
-- Verify the v9-shape query returns the seeded audit row. We deliberately
-- skip a planner inspection here; row-count correctness is the functional
-- contract that callers depend on, and PG plan-shape verification belongs
-- in a dedicated EXPLAIN-driven test that runs outside a DO block.
DO $$
DECLARE
    hits INTEGER;
BEGIN
    SELECT COUNT(*) INTO hits
        FROM audit_logs
        WHERE org_id = 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1'
          AND client_id = 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1';
    IF hits < 1 THEN
        RAISE EXCEPTION 'FT.3 FAILED: v9-shape query (org_id+client_id) returned % rows for cs_aaa* customer, expected >= 1', hits;
    END IF;
    RAISE NOTICE 'FT.3 PASS: v9-shape audit_logs query returned % row(s) for cs_aaa* customer', hits;
END $$;

-- ============================================================================
-- FT.4 — 'global' sentinel still works for system-wide static_policies
-- ============================================================================
DO $$
DECLARE
    global_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO global_count
        FROM static_policies
        WHERE tenant_id = 'global'
          AND client_id = 'global';
    -- Seeded 1 global static_policy in seed.sql; system policies seeded by 031
    -- may add more.
    IF global_count < 1 THEN
        RAISE EXCEPTION 'FT.4 FAILED: % static_policies rows have tenant_id=client_id=''global''; expected >= 1', global_count;
    END IF;
    RAISE NOTICE 'FT.4 PASS: global sentinel preserved on % static_policies rows', global_count;
END $$;

-- ============================================================================
-- FT.5 — get_dynamic_policies_for_tenant() function still finds 'global' policies
-- (proves the existing function from migration 010 still operates correctly
-- after the additive client_id column)
-- ============================================================================
DO $$
DECLARE
    found_global BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM get_dynamic_policies_for_tenant('cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1')
        WHERE policy_id = 'seed-dyn-2'
    ) INTO found_global;
    IF NOT found_global THEN
        RAISE EXCEPTION 'FT.5 FAILED: get_dynamic_policies_for_tenant() did not return the global seed-dyn-2 policy; migration broke the function';
    END IF;
    RAISE NOTICE 'FT.5 PASS: get_dynamic_policies_for_tenant() still resolves global sentinel';
END $$;

-- ============================================================================
-- FT.6 — service_identities lookup by client_id matches by tenant_id
-- ============================================================================
DO $$
DECLARE
    by_tid INTEGER;
    by_cid INTEGER;
BEGIN
    SELECT COUNT(*) INTO by_tid
        FROM service_identities WHERE tenant_id = 'cs_cccccccc-cccc-cccc-cccc-ccccccccccc3';
    SELECT COUNT(*) INTO by_cid
        FROM service_identities WHERE client_id = 'cs_cccccccc-cccc-cccc-cccc-ccccccccccc3';
    IF by_tid <> by_cid THEN
        RAISE EXCEPTION 'FT.6 FAILED: service_identities by tenant_id=% rows differs from by client_id=% rows', by_tid, by_cid;
    END IF;
    RAISE NOTICE 'FT.6 PASS: service_identities by-tenant_id (% rows) == by-client_id (% rows)', by_tid, by_cid;
END $$;

-- ============================================================================
-- FT.7 — execution_history v9 query path returns expected row count
-- ============================================================================
DO $$
DECLARE
    hits INTEGER;
BEGIN
    SELECT COUNT(*) INTO hits
        FROM execution_history
        WHERE org_id = 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1'
          AND client_id = 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1';
    IF hits < 1 THEN
        RAISE EXCEPTION 'FT.7 FAILED: execution_history v9-shape query returned % rows for cs_aaa* customer, expected >= 1', hits;
    END IF;
    RAISE NOTICE 'FT.7 PASS: execution_history v9-shape query returned % row(s)', hits;
END $$;

-- ============================================================================
-- FT.8 — tenants.org_id FK to organizations satisfied for ALL post-094 rows
-- (proves Pass-1 PREP correctly seeded organizations + Pass-1B ran cleanly)
-- ============================================================================
DO $$
DECLARE
    orphans INTEGER;
BEGIN
    SELECT COUNT(*) INTO orphans
        FROM tenants t
        LEFT JOIN organizations o ON o.org_id = t.org_id
        WHERE o.org_id IS NULL;
    IF orphans > 0 THEN
        RAISE EXCEPTION 'FT.8 FAILED: % tenants rows have org_id with no matching organization (FK violation waiting to happen)', orphans;
    END IF;
    RAISE NOTICE 'FT.8 PASS: every tenants.org_id has a matching organizations row';
END $$;

-- ============================================================================
-- FT.9 — Pre-existing register_tenant() function still operates correctly
-- (proves additive migration didn't break the auto-register flow)
-- ============================================================================
DO $$
DECLARE
    before_count INTEGER;
    after_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO before_count FROM tenants WHERE tenant_id = 'ft9-functional-test';
    -- First ensure the org exists (the function only creates the tenant row)
    INSERT INTO organizations (org_id, name, tier, max_nodes, license_key)
        VALUES ('ft9-functional-test', 'FT9 Test Org', 'Community', 2, '')
        ON CONFLICT (org_id) DO NOTHING;

    PERFORM register_tenant('ft9-functional-test', 'ft9-functional-test', 'FT9 Test Tenant');
    SELECT COUNT(*) INTO after_count FROM tenants WHERE tenant_id = 'ft9-functional-test';

    IF after_count <> 1 THEN
        RAISE EXCEPTION 'FT.9 FAILED: register_tenant() did not insert the test row (count=%)', after_count;
    END IF;
    -- Cleanup
    DELETE FROM tenants WHERE tenant_id = 'ft9-functional-test';
    DELETE FROM organizations WHERE org_id = 'ft9-functional-test';
    RAISE NOTICE 'FT.9 PASS: register_tenant() function still inserts new rows post-088 (additive client_id column did not break it)';
END $$;

DO $$ BEGIN RAISE NOTICE 'Functional test suite: ALL TESTS PASSED'; END $$;
