-- Assertion suite for migration 088 — v9 credential client_id additive layer.
--
-- Apply AFTER migration 088. RAISEs EXCEPTION on any invariant violation
-- so psql exits non-zero, suitable for CI gating.
--
-- Pre-condition: the target tables exist on the test DB (i.e. migrations
-- 062, 068, 077 have been applied alongside their dependencies).

-- ----------------------------------------------------------------------------
-- Schema invariants
-- ----------------------------------------------------------------------------

-- 088.1 — client_id column exists on community_saas_registrations
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'community_saas_registrations' AND column_name = 'client_id') THEN
        RAISE EXCEPTION 'Test 088.1 FAILED: community_saas_registrations.client_id missing';
    END IF;
    RAISE NOTICE 'Test 088.1 PASS: community_saas_registrations.client_id present';
END $$;

-- 088.2 — client_id column exists on tenants
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'tenants' AND column_name = 'client_id') THEN
        RAISE EXCEPTION 'Test 088.2 FAILED: tenants.client_id missing';
    END IF;
    RAISE NOTICE 'Test 088.2 PASS: tenants.client_id present';
END $$;

-- 088.3 — client_id column exists on plugin_user_licenses
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'plugin_user_licenses' AND column_name = 'client_id') THEN
        RAISE EXCEPTION 'Test 088.3 FAILED: plugin_user_licenses.client_id missing';
    END IF;
    RAISE NOTICE 'Test 088.3 PASS: plugin_user_licenses.client_id present';
END $$;

-- 088.4 — indexes exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'uq_csaas_reg_client_id') THEN
        RAISE EXCEPTION 'Test 088.4a FAILED: uq_csaas_reg_client_id missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_tenants_client_id') THEN
        RAISE EXCEPTION 'Test 088.4b FAILED: idx_tenants_client_id missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_plugin_lic_client_id') THEN
        RAISE EXCEPTION 'Test 088.4c FAILED: idx_plugin_lic_client_id missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_plugin_lic_client_active') THEN
        RAISE EXCEPTION 'Test 088.4d FAILED: idx_plugin_lic_client_active missing';
    END IF;
    RAISE NOTICE 'Test 088.4 PASS: all 088 indexes present';
END $$;

-- 088.5 — plugin_user_licenses FK to community_saas_registrations(tenant_id) preserved
-- (forward migration must NOT touch the existing FK)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.referential_constraints rc
        JOIN information_schema.key_column_usage kcu USING (constraint_name)
        WHERE kcu.table_name = 'plugin_user_licenses' AND kcu.column_name = 'tenant_id'
    ) THEN
        RAISE EXCEPTION 'Test 088.5 FAILED: plugin_user_licenses.tenant_id FK was dropped — migration was supposed to leave it alone';
    END IF;
    RAISE NOTICE 'Test 088.5 PASS: plugin_user_licenses.tenant_id FK preserved';
END $$;

-- ----------------------------------------------------------------------------
-- Data invariants
-- ----------------------------------------------------------------------------

-- 088.6 — for every row with non-empty tenant_id, client_id is also populated
--          (i.e. the backfill UPDATE ran successfully)
DO $$
DECLARE
    csaas_unbackfilled  INTEGER;
    tenants_unbackfilled INTEGER;
    plugin_unbackfilled INTEGER;
BEGIN
    SELECT COUNT(*) INTO csaas_unbackfilled
        FROM community_saas_registrations
        WHERE (client_id IS NULL OR client_id = '')
          AND tenant_id IS NOT NULL AND tenant_id <> '';
    IF csaas_unbackfilled > 0 THEN
        RAISE EXCEPTION 'Test 088.6a FAILED: community_saas_registrations has % rows with empty client_id but populated tenant_id', csaas_unbackfilled;
    END IF;

    SELECT COUNT(*) INTO tenants_unbackfilled
        FROM tenants
        WHERE (client_id IS NULL OR client_id = '')
          AND tenant_id IS NOT NULL AND tenant_id <> '';
    IF tenants_unbackfilled > 0 THEN
        RAISE EXCEPTION 'Test 088.6b FAILED: tenants has % rows with empty client_id but populated tenant_id', tenants_unbackfilled;
    END IF;

    SELECT COUNT(*) INTO plugin_unbackfilled
        FROM plugin_user_licenses
        WHERE (client_id IS NULL OR client_id = '')
          AND tenant_id IS NOT NULL AND tenant_id <> '';
    IF plugin_unbackfilled > 0 THEN
        RAISE EXCEPTION 'Test 088.6c FAILED: plugin_user_licenses has % rows with empty client_id but populated tenant_id', plugin_unbackfilled;
    END IF;

    RAISE NOTICE 'Test 088.6 PASS: all rows with non-empty tenant_id have backfilled client_id';
END $$;

-- 088.7 — backfilled client_id equals tenant_id (no semantic drift)
DO $$
DECLARE
    mismatches INTEGER;
BEGIN
    SELECT COUNT(*) INTO mismatches
        FROM community_saas_registrations
        WHERE tenant_id IS NOT NULL AND tenant_id <> ''
          AND client_id IS NOT NULL AND client_id <> ''
          AND client_id <> tenant_id;
    IF mismatches > 0 THEN
        RAISE EXCEPTION 'Test 088.7 FAILED: % community_saas_registrations rows have client_id <> tenant_id (data drift)', mismatches;
    END IF;
    RAISE NOTICE 'Test 088.7 PASS: client_id matches tenant_id on all populated rows';
END $$;

DO $$ BEGIN RAISE NOTICE 'Migration 088 assertion suite: ALL TESTS PASSED'; END $$;
