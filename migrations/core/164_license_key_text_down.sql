-- Migration 164 DOWN: no-op, deliberately
-- Pairs with: 164_license_key_text.sql
--
-- Narrowing TEXT back to VARCHAR(512) would fail outright (or, worse, invite a
-- USING clause that truncates) on any organizations row whose licence key is
-- longer than 512 characters - exactly the rows the UP migration exists to
-- admit. A licence key truncated at 512 characters no longer validates, so a
-- "successful" narrowing would corrupt live licences. Rolling the CODE back is
-- safe without narrowing the column: every reader treats license_key as an
-- opaque string.
--
-- This file exists so the up/down pairing stays satisfied and so the reasoning
-- is recorded next to the migration rather than in a PR.

BEGIN;

DO $$
BEGIN
    RAISE NOTICE 'Migration 164 DOWN: intentional no-op (narrowing license_key could truncate or reject valid stored licences)';
END $$;

COMMIT;
