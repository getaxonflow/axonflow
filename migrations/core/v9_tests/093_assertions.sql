-- Assertion suite for migration 093 — saml_configurations classification.

-- 093.1 — table comment updated with v9 classification
DO $$
DECLARE
    cmt TEXT;
BEGIN
    SELECT obj_description('public.saml_configurations'::regclass, 'pg_class') INTO cmt;
    IF cmt IS NULL OR cmt NOT LIKE '%class (b)%' THEN
        RAISE EXCEPTION 'Test 093.1 FAILED: saml_configurations table comment lacks v9 class (b) marker (got: %)', cmt;
    END IF;
    RAISE NOTICE 'Test 093.1 PASS: saml_configurations table classification recorded';
END $$;

-- 093.2 — org_id NOT NULL invariant
DO $$
DECLARE
    bad INTEGER;
BEGIN
    SELECT COUNT(*) INTO bad
        FROM saml_configurations
        WHERE org_id IS NULL OR org_id = '';
    IF bad > 0 THEN
        RAISE EXCEPTION 'Test 093.2 FAILED: saml_configurations has % rows with empty org_id (invariant violated)', bad;
    END IF;
    RAISE NOTICE 'Test 093.2 PASS: saml_configurations org_id NOT NULL invariant holds';
END $$;

-- 093.3 — no client_id column added (class b — should remain org-only)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'saml_configurations' AND column_name = 'client_id') THEN
        RAISE EXCEPTION 'Test 093.3 FAILED: saml_configurations.client_id should NOT exist — class (b) is org-only';
    END IF;
    RAISE NOTICE 'Test 093.3 PASS: saml_configurations correctly has no client_id';
END $$;

DO $$ BEGIN RAISE NOTICE 'Migration 093 assertion suite: ALL TESTS PASSED'; END $$;
