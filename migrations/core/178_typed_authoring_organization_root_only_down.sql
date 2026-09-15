-- Migration 178 DOWN: restore the typed-authoring root CHECKs to
-- ('system', 'organization'), as migrations/core/176 created them.
--
-- This widens what the schema admits and nothing more. It writes no row and
-- authorizes no key; the Go store keeps refusing the system root
-- (platform/policy/authoringstore ErrSystemRootNotStored) whatever the schema
-- allows.
--
-- REMOVING A SYSTEM-ROOT ROW THAT MIGRATION 178 REFUSED ON
--
-- Migration 178 fails, and changes nothing, when any of the three tables holds a
-- row whose root is not 'organization'. Such a row has no legitimate writer
-- (#4047), so it is evidence and is removed by a person after review, never by a
-- boot:
--
--   1. Find it as a role that BYPASSES row-level security - FORCE ROW LEVEL
--      SECURITY binds the table owner, so the owner alone reads only the rows of
--      the organization its app.current_org_id names:
--        SELECT org_id, root, digest FROM typed_policy_artifacts WHERE root <> 'organization';
--        SELECT org_id, root, seq, digest FROM typed_policy_activations WHERE root <> 'organization';
--        SELECT org_id, root, key_id FROM typed_policy_signing_keys WHERE root <> 'organization';
--   2. The tables are append-only by trigger (core/176). As the table owner, in
--      one transaction: disable the row trigger
--      (typed_policy_artifacts_no_update_delete,
--       typed_policy_activations_no_update_delete or
--       typed_policy_signing_keys_revoke_only), delete the reviewed row by its
--      primary key, and re-enable the trigger.
--   3. Re-run migrations.

BEGIN;

ALTER TABLE typed_policy_artifacts DROP CONSTRAINT IF EXISTS typed_policy_artifacts_root_chk;
ALTER TABLE typed_policy_artifacts
    ADD CONSTRAINT typed_policy_artifacts_root_chk CHECK (root IN ('system', 'organization'));

ALTER TABLE typed_policy_activations DROP CONSTRAINT IF EXISTS typed_policy_activations_root_chk;
ALTER TABLE typed_policy_activations
    ADD CONSTRAINT typed_policy_activations_root_chk CHECK (root IN ('system', 'organization'));

ALTER TABLE typed_policy_signing_keys DROP CONSTRAINT IF EXISTS typed_policy_signing_keys_root_chk;
ALTER TABLE typed_policy_signing_keys
    ADD CONSTRAINT typed_policy_signing_keys_root_chk CHECK (root IN ('system', 'organization'));

COMMIT;
