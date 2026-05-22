-- Down migration for 093: restore the pre-093 COMMENT state on saml_configurations.
-- Pairs with: 093_v9_saml_configurations_classification.sql
--
-- The forward migration only wrote COMMENT metadata + ran a read-only
-- verification SELECT. Rollback restores the original COMMENT text from
-- migration 002 (preserved verbatim below) so pg_dump output matches
-- pre-093 byte-for-byte.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'saml_configurations') THEN
        EXECUTE 'COMMENT ON TABLE saml_configurations IS ''SAML SSO configurations per organization''';
        EXECUTE 'COMMENT ON COLUMN saml_configurations.org_id IS NULL';
        RAISE NOTICE 'Migration 093 DOWN: saml_configurations comments restored to pre-093 state';
    END IF;
END $$;
