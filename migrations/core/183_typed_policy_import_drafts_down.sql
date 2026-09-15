-- Migration 183 DOWN: drop typed_policy_import_drafts and typed_policy_import_candidates()
-- Date: 2026-09-13
--
-- ROLL THE BINARIES BACK FIRST, though it is not load-bearing here: from this
-- migration on the agent's boot step reads typed_policy_import_candidates(), and
-- it checks for the function first and skips when the schema has none.
--
-- Every recorded import goes with the table, the dismissals with it.
-- policy_overrides is untouched, so re-applying 183 imports again at the next
-- boot, and an organization that had dismissed its draft sees a new one.

BEGIN;

DO $$
DECLARE
    import_rows INTEGER := 0;
    counted     BOOLEAN := false;
BEGIN
    BEGIN
        SET LOCAL row_security = off;
        IF to_regclass('typed_policy_import_drafts') IS NOT NULL THEN
            EXECUTE 'SELECT COUNT(*) FROM typed_policy_import_drafts' INTO import_rows;
        END IF;
        counted := true;
    EXCEPTION WHEN OTHERS THEN
        counted := false;
    END;
    SET LOCAL row_security = on;
    IF counted THEN
        RAISE NOTICE 'Migration 183 down: dropping % recorded import(s); the next boot of a binary with 183 would import again.', import_rows;
    ELSE
        RAISE NOTICE 'Migration 183 down: row count UNAVAILABLE (this role cannot read the FORCE-RLS table); dropping every recorded import.';
    END IF;
END $$;

DROP TABLE IF EXISTS typed_policy_import_drafts;
DROP FUNCTION IF EXISTS typed_policy_import_drafts_guard();
DROP FUNCTION IF EXISTS typed_policy_import_candidates();

DO $$
BEGIN
    IF to_regclass('typed_policy_import_drafts') IS NOT NULL THEN
        RAISE EXCEPTION 'Migration 183 down failed: typed_policy_import_drafts still exists';
    END IF;
    IF to_regprocedure('public.typed_policy_import_candidates()') IS NOT NULL THEN
        RAISE EXCEPTION 'Migration 183 down failed: typed_policy_import_candidates() still exists';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc WHERE proname = 'typed_policy_import_drafts_guard') THEN
        RAISE EXCEPTION 'Migration 183 down failed: typed_policy_import_drafts_guard() still exists';
    END IF;
    RAISE NOTICE 'Migration 183 down verified: typed_policy_import_drafts and its functions are gone.';
END $$;

COMMIT;
