-- Migration 176 DOWN: remove typed authoring persistence
-- Date: 2026-09-10
-- Purpose: Reverse migrations/core/176_typed_authoring_persistence.sql.
-- Related: #3975, #3776
--
-- THIS IS THE SINGLE ROLLBACK PATH FOR THE THREE TABLES, ON EVERY EDITION.
--
-- migrations/enterprise/155 created the same three tables on deployments that
-- applied the enterprise category, and 176 is a no-op there. Two migrations
-- creating one set of tables must not both drop them: on a database carrying
-- both records, whichever rolled back first would destroy the other's state
-- while its own row still claimed to be applied. So 155's down is now a no-op
-- that says why, and this file is the rollback — including for a deployment
-- whose tables were physically created by 155.
--
-- WHAT THIS DESTROYS, SAID PLAINLY BEFORE IT HAPPENS
--
-- Rolling this back deletes every persisted policy artifact, the entire audited
-- activation history, and every signing-key authorization. The deployment does
-- not fall back to an earlier durable state — it falls back to the in-process
-- store, which starts empty on the next boot, and on Community that is the
-- defect #3975 was filed for. The counts are raised as a NOTICE first so an
-- operator running this by hand sees what the rollback is about to cost.
--
-- WHY THE COUNT NEEDS row_security OFF, AND WHY IT NEEDS A HANDLER AROUND IT
--
-- All three tables are FORCE ROW LEVEL SECURITY with a strict org-equality
-- policy, and a down migration runs with no organization scope set, so
-- current_setting('app.current_org_id', true) is NULL and every row is
-- invisible. A COUNT without this reports 0 on a populated table and the notice
-- is a comfortable lie.
--
-- BUT `row_security = off` DOES NOT BYPASS RLS. For a role without BYPASSRLS it
-- converts an RLS-affected query into a hard error:
--
--     ERROR: 42501: query would be affected by row-level security policy
--            for table "typed_policy_artifacts"
--
-- and with the setting at TRANSACTION scope and no handler, that error aborts
-- THE ENTIRE ROLLBACK — unconditionally, on an empty table as much as a full
-- one. It succeeds only for a superuser, which is why it is invisible on a
-- developer box and fatal on a deployment whose migration role is merely the
-- table owner. That is the population every FORCE-RLS decision here is written
-- for, and it is the #3635 class that
-- TestEveryDownMigrationCountingAFORCERLSTableDisablesRowSecurity now pins.
--
-- So the setting sits INSIDE the block, with an EXCEPTION arm and a `counted`
-- flag: a role that cannot read the tables reports the counts as UNAVAILABLE
-- rather than inventing a zero or aborting the rollback. The shape is
-- core/171_principal_admissions_down.sql's.

BEGIN;

DO $$
DECLARE
    artifacts   INTEGER := 0;
    activations INTEGER := 0;
    keys        INTEGER := 0;
    counted     BOOLEAN := false;
BEGIN
    BEGIN
        SET LOCAL row_security = off;
        IF to_regclass('typed_policy_artifacts') IS NOT NULL THEN
            EXECUTE 'SELECT COUNT(*) FROM typed_policy_artifacts' INTO artifacts;
        END IF;
        IF to_regclass('typed_policy_activations') IS NOT NULL THEN
            EXECUTE 'SELECT COUNT(*) FROM typed_policy_activations' INTO activations;
        END IF;
        IF to_regclass('typed_policy_signing_keys') IS NOT NULL THEN
            EXECUTE 'SELECT COUNT(*) FROM typed_policy_signing_keys' INTO keys;
        END IF;
        counted := true;
    EXCEPTION WHEN OTHERS THEN
        counted := false;
    END;
    SET LOCAL row_security = on;

    IF counted THEN
        RAISE NOTICE 'Migration 176 down: dropping % artifact(s), % activation record(s) and % signing-key authorization(s); typed authoring reverts to the in-process store and loses everything on the next restart.',
            artifacts, activations, keys;
    ELSE
        RAISE NOTICE 'Migration 176 down: row counts UNAVAILABLE (this role cannot read the FORCE-RLS tables); dropping every persisted artifact, activation record and signing-key authorization. Typed authoring reverts to the in-process store.';
    END IF;
END $$;

-- The triggers and policies go with the tables; they are dropped explicitly
-- anyway so that a partially applied 176 (tables present, triggers not, or the
-- reverse) still comes back to a clean state.
DROP TRIGGER IF EXISTS typed_policy_artifacts_no_update_delete    ON typed_policy_artifacts;
DROP TRIGGER IF EXISTS typed_policy_artifacts_no_truncate         ON typed_policy_artifacts;
DROP TRIGGER IF EXISTS typed_policy_activations_no_update_delete  ON typed_policy_activations;
DROP TRIGGER IF EXISTS typed_policy_activations_no_truncate       ON typed_policy_activations;
DROP TRIGGER IF EXISTS typed_policy_signing_keys_revoke_only      ON typed_policy_signing_keys;
DROP TRIGGER IF EXISTS typed_policy_signing_keys_no_truncate      ON typed_policy_signing_keys;

DROP TABLE IF EXISTS typed_policy_activations;
DROP TABLE IF EXISTS typed_policy_artifacts;
DROP TABLE IF EXISTS typed_policy_signing_keys;

-- The trigger functions are dropped only after their last user is gone.
DROP FUNCTION IF EXISTS typed_policy_signing_keys_revoke_only();
DROP FUNCTION IF EXISTS typed_policy_append_only();

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['typed_policy_artifacts', 'typed_policy_activations', 'typed_policy_signing_keys'] LOOP
        IF to_regclass(t) IS NOT NULL THEN
            RAISE EXCEPTION 'Migration 176 down failed: % still exists', t;
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc WHERE proname = 'typed_policy_append_only') THEN
        RAISE EXCEPTION 'Migration 176 down failed: typed_policy_append_only() still exists';
    END IF;
    RAISE NOTICE 'Migration 176 down verified: all three typed-authoring tables and both trigger functions are gone.';
END $$;

COMMIT;
