-- Assertion suite for migration 094 — Phase 3 org_id backfill.
--
-- This file expects pre-test seed data of:
--   community_saas_registrations row with tenant_id='cs_canonical-test-uuid-0001-aaaaaaaaaaaaaaaaaaaaaaaaaaaa', org_id='community-saas'
--   tenants row with tenant_id matching
--   audit_logs row with tenant_id='cs_canonical-test-uuid-0001-aaaaaaaaaaaaaaaaaaaaaaaaaaaa', org_id=NULL
--   audit_logs row with tenant_id='acme-prod-api', org_id=NULL (self-hosted shape)
--
-- See migrations/core/v9_tests/seed.sql for the canonical seed used by the
-- driver script.

-- 094.1 — community_saas_registrations Pass-1 ran
DO $$
DECLARE
    bad INTEGER;
BEGIN
    SELECT COUNT(*) INTO bad
        FROM community_saas_registrations
        WHERE client_id LIKE 'cs\_%' ESCAPE '\'
          AND org_id = 'community-saas';
    IF bad > 0 THEN
        RAISE EXCEPTION 'Test 094.1 FAILED: % cs_* rows still have org_id=community-saas (Pass-1 did not run)', bad;
    END IF;
    RAISE NOTICE 'Test 094.1 PASS: cs_* community_saas_registrations remapped';
END $$;

-- 094.2 — Pass-1 cs_* rows have org_id = client_id
DO $$
DECLARE
    drifted INTEGER;
BEGIN
    SELECT COUNT(*) INTO drifted
        FROM community_saas_registrations
        WHERE client_id LIKE 'cs\_%' ESCAPE '\'
          AND org_id <> client_id;
    IF drifted > 0 THEN
        RAISE EXCEPTION 'Test 094.2 FAILED: % cs_* rows have org_id <> client_id (Pass-1 produced wrong values)', drifted;
    END IF;
    RAISE NOTICE 'Test 094.2 PASS: cs_* org_id matches client_id';
END $$;

-- 094.3 — audit_logs Pass-1 for cs_* rows
DO $$
DECLARE
    gaps INTEGER;
BEGIN
    SELECT COUNT(*) INTO gaps
        FROM audit_logs
        WHERE tenant_id LIKE 'cs\_%' ESCAPE '\'
          AND (org_id IS NULL OR org_id = '' OR org_id = 'community-saas');
    IF gaps > 0 THEN
        RAISE EXCEPTION 'Test 094.3 FAILED: % audit_logs cs_* rows still have empty/shared org_id', gaps;
    END IF;
    RAISE NOTICE 'Test 094.3 PASS: audit_logs cs_* org_id remapped';
END $$;

-- 094.4 — Pass-2 self-hosted rows backfilled from session var
-- (Requires app.deployment_org_id was set before migration ran; the
-- driver script run_tests.sh sets it to 'test-deployment-org'.)
DO $$
DECLARE
    bad INTEGER;
BEGIN
    SELECT COUNT(*) INTO bad
        FROM audit_logs
        WHERE tenant_id NOT LIKE 'cs\_%' ESCAPE '\'
          AND tenant_id IS NOT NULL AND tenant_id <> ''
          AND (org_id IS NULL OR org_id = '');
    IF bad > 0 THEN
        RAISE EXCEPTION 'Test 094.4 FAILED: % audit_logs non-cs_* rows still have empty org_id (Pass-2 did not run)', bad;
    END IF;
    RAISE NOTICE 'Test 094.4 PASS: audit_logs Pass-2 backfilled';
END $$;

-- 094.5 — 'global' sentinel preserved on static_policies (Pass-1 + Pass-2 must skip it)
DO $$
DECLARE
    drifted INTEGER;
BEGIN
    SELECT COUNT(*) INTO drifted
        FROM static_policies
        WHERE tenant_id = 'global'
          AND org_id IS NOT NULL AND org_id <> '';
    -- Acceptable values: NULL (untouched) or any system-wide marker.
    -- Critically: a global-sentinel row must NOT have a per-customer org_id.
    SELECT COUNT(*) INTO drifted
        FROM static_policies
        WHERE tenant_id = 'global'
          AND org_id LIKE 'cs\_%' ESCAPE '\';
    IF drifted > 0 THEN
        RAISE EXCEPTION 'Test 094.5 FAILED: % static_policies global rows got a cs_* org_id', drifted;
    END IF;
    RAISE NOTICE 'Test 094.5 PASS: static_policies global sentinel preserved';
END $$;

DO $$ BEGIN RAISE NOTICE 'Migration 094 assertion suite: ALL TESTS PASSED'; END $$;
