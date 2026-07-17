-- Migration 144 DOWN: re-tighten the detection-posture category CHECK
-- Issue: #2958
--
-- Reverts migration 144 by restoring mig 120's four-value category CHECK.
--
-- DESTRUCTIVE BY NECESSITY: any org that set an obligation_fallback posture
-- holds a row this constraint will no longer admit, so the rows MUST be deleted
-- BEFORE the constraint is re-added — otherwise ADD CONSTRAINT fails on the
-- existing rows and the whole down migration aborts. This is the same
-- "a down migration must not assume the up migration's data is absent" class
-- that core/142's api_keys down-gate exists to handle. The delete is announced
-- in a NOTICE with the row count so a rollback is never silent about the
-- posture it discarded.
--
-- Behavior after a rollback: an org that had obligation_fallback=block reverts
-- to the resolver's default (log) — the 9.11.0 agent treats "no row" as log.
-- Rolling the AGENT back to <9.11.0 as well restores the pre-#2958 behavior
-- (the obligation is emitted to every seam, and a headers-only adapter fails
-- closed on it).

BEGIN;

-- detection_action_overrides is ENABLE + FORCE ROW LEVEL SECURITY (mig 120),
-- and its policy keys on the app.current_org_id GUC — which a migration does
-- not set. Migrations run on the owner / axonflow_platform_admin (BYPASSRLS)
-- connection, never axonflow_app_role (mig 098), so the DELETE below sees every
-- row. row_security=off makes that a GUARANTEE rather than an assumption: under
-- a role that does NOT bypass RLS it turns the dangerous silent failure — a
-- DELETE that matches zero rows because RLS filtered them, followed by an ADD
-- CONSTRAINT that fails on the survivors it could not see — into a loud error
-- at the DELETE itself. It is a no-op for a bypassing role.
SET LOCAL row_security = off;

-- Announce, then delete, the rows the re-tightened constraint cannot hold.
DO $$
DECLARE
    doomed BIGINT;
BEGIN
    SELECT count(*) INTO doomed
    FROM detection_action_overrides
    WHERE category = 'obligation_fallback';

    IF doomed > 0 THEN
        RAISE NOTICE 'Migration 144 down: deleting % obligation_fallback posture row(s) — affected orgs revert to the default (log) on a 9.11.0+ agent', doomed;
    END IF;
END
$$;

DELETE FROM detection_action_overrides WHERE category = 'obligation_fallback';

ALTER TABLE detection_action_overrides
    DROP CONSTRAINT IF EXISTS detection_action_overrides_category_chk;

ALTER TABLE detection_action_overrides
    ADD CONSTRAINT detection_action_overrides_category_chk
    CHECK (category IN ('pii', 'sqli', 'dangerous_query', 'dangerous_command'));

-- Restore mig 120's column comment verbatim.
COMMENT ON COLUMN detection_action_overrides.category IS
    'Detection category: pii | sqli | dangerous_query | dangerous_command.';

-- Verification — the rollback must be complete, not partial.
DO $$
DECLARE
    def TEXT;
    leftover BIGINT;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO def
    FROM pg_constraint
    WHERE conname = 'detection_action_overrides_category_chk'
      AND conrelid = 'detection_action_overrides'::regclass;

    IF def IS NULL THEN
        RAISE EXCEPTION 'Migration 144 down failed: detection_action_overrides_category_chk not restored';
    END IF;
    IF def LIKE '%obligation_fallback%' THEN
        RAISE EXCEPTION 'Migration 144 down failed: category CHECK still admits obligation_fallback (definition: %)', def;
    END IF;

    SELECT count(*) INTO leftover
    FROM detection_action_overrides
    WHERE category = 'obligation_fallback';
    IF leftover > 0 THEN
        RAISE EXCEPTION 'Migration 144 down failed: % obligation_fallback row(s) survived the delete', leftover;
    END IF;
    RAISE NOTICE 'Migration 144 down verified: category CHECK restored to the original four, no obligation_fallback rows remain';
END
$$;

COMMIT;
