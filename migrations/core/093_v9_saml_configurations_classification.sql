-- Migration 093: v9 saml_configurations classification (org-scoped)
-- Date: 2026-05-19
--
-- Classification: customer/account identity. SAML SSO configurations are
-- inherently org-scoped (one IdP per organization), not per-credential. The
-- existing schema in migration 002 already reflects this:
--
--   saml_configurations.org_id VARCHAR(255) UNIQUE NOT NULL
--
-- There is no tenant_id column to migrate from, and org_id is already
-- populated by the CREATE TABLE NOT NULL constraint. No additive schema
-- change is needed.
--
-- This migration exists to:
--   (1) Document the v9 classification on-record via COMMENT, so future
--       FORCE RLS work doesn't accidentally try to add client_id here.
--   (2) Provide a verification query that asserts no row has empty
--       org_id. Fails loudly if invariant is violated (defensive — the
--       UNIQUE NOT NULL constraint should make this impossible).
--   (3) Sit at the next sequential migration number so the v9 sweep is
--       contiguous in the schema_migrations history.
--
-- Idempotency: COMMENT is overwrite-safe; verification SELECT only reads.
-- Rollback: paired _down.sql restores the previous (empty) comment.
--
-- Depends on: 002_organizations_and_auth

DO $$
DECLARE
    empty_org_id_rows INTEGER;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'saml_configurations') THEN
        EXECUTE 'COMMENT ON TABLE saml_configurations IS ''SAML SSO configurations per organization. Org-scoped — does NOT carry client_id; one IdP per org by design.''';

        EXECUTE 'COMMENT ON COLUMN saml_configurations.org_id IS ''Customer/account identity column. UNIQUE NOT NULL since migration 002 — one IdP per org by design.''';

        -- Defensive verification: assert the NOT NULL invariant holds.
        SELECT COUNT(*) INTO empty_org_id_rows
            FROM saml_configurations
            WHERE org_id IS NULL OR org_id = '';

        IF empty_org_id_rows > 0 THEN
            RAISE EXCEPTION 'Migration 093: saml_configurations has % rows with empty org_id, violating UNIQUE NOT NULL invariant. Investigate before proceeding to FORCE RLS.', empty_org_id_rows;
        END IF;

        RAISE NOTICE 'Migration 093: saml_configurations classification recorded (org-scoped, no client_id)';
    ELSE
        RAISE NOTICE 'Migration 093: saml_configurations missing — skipping (not all deployment modes load 002)';
    END IF;
END $$;
