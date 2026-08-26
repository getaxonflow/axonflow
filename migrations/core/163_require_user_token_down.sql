-- Migration 163 DOWN: remove require_user_token from organizations (#3476).
-- Existence-guarded like the up migration.

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        -- to_regclass, not information_schema: information_schema views are
        -- PRIVILEGE-FILTERED, so a role without a privilege on organizations
        -- reads "table absent", takes the skip branch and COMMITS having done
        -- nothing. pg_catalog is not filtered. Matches migrations 161/162.
        SELECT 1 WHERE to_regclass('public.organizations') IS NOT NULL
    ) THEN
        ALTER TABLE organizations DROP COLUMN IF EXISTS require_user_token;
        RAISE NOTICE 'Migration 163 down: require_user_token removed from organizations';
    END IF;
END $$;

COMMIT;
