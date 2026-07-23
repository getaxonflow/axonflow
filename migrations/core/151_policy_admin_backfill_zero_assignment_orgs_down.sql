-- Migration 151 DOWN: remove exactly the policy_admin rows 151 inserted (#3004)
-- Date: 2026-07-22
--
-- The UP stamps assigned_by = 'migration:151_policy_admin_backfill' on every row
-- it inserts. Because the INSERT is ON CONFLICT DO NOTHING, a pre-existing
-- assignment for the same (org_id, user_email, role_id) keeps ITS assigned_by
-- and is never rewritten — so the only rows carrying that marker are ones a run
-- of THIS migration created. Deleting on the marker therefore removes exactly
-- what was added and leaves manual/SCIM/other-migration assignments untouched.
--
-- NOTE: rolling this back re-opens the #3004 lockout for those orgs (their
-- password-login identity loses policy:write again with no in-product
-- recovery). Roll back the platform binary alongside it, or grant the role
-- another way first.

BEGIN;

DO $$
DECLARE
    v_removed INTEGER := 0;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'role_assignments'
    ) THEN
        RAISE NOTICE 'Migration 151 down: role_assignments absent - skipping';
        RETURN;
    END IF;

    DELETE FROM role_assignments
     WHERE assigned_by = 'migration:151_policy_admin_backfill';

    GET DIAGNOSTICS v_removed = ROW_COUNT;
    RAISE NOTICE 'Migration 151 down: removed % backfilled policy_admin assignment(s)', v_removed;
END $$;

COMMIT;
