-- Migration 178: Typed authoring persistence holds organization-root policy only
-- Date: 2026-09-11
-- Purpose: Narrow the `root` CHECK on typed_policy_artifacts,
--          typed_policy_activations and typed_policy_signing_keys from
--          ('system', 'organization') to 'organization', so that no writer -
--          this repository's Go, a script, or a writer not yet written - can
--          record a system-root artifact, activation or signing key.
-- Related: #4047 (an organization's signing key authorized under the system
--          root), #3884 (the system-root authority), #3786,
--          technical-docs/designs/SYSTEM_ROOT_SIGNING_AUTHORITY.md,
--          migrations/core/176 (the tables).
--
-- EDITION: COMMUNITY (mirrored). The three tables belong to core/176, which
-- ships on every edition, so the line they hold ships on every edition too.
-- migrations/enterprise/155 created the same tables with the same constraint
-- NAMES on the deployments that ran it, so this one file covers both.
--
-- ---------------------------------------------------------------------------
-- WHY THE SCHEMA, AND NOT ONLY THE GO
-- ---------------------------------------------------------------------------
--
-- The system root's authority is the corpus this binary shipped: a digest
-- compiled into the binary (arm 1 of SYSTEM_ROOT_SIGNING_AUTHORITY.md), signed
-- per process for the engine that enforces it, and never stored. No operator
-- key is authorized under it at v11.0.0. A durable system-root row therefore
-- has no legitimate writer, and a system-root key row would be authority
-- granted by whoever could insert it.
--
-- platform/policy/authoringstore refuses the root in Go (ErrSystemRootNotStored).
-- This CHECK binds every connection that can write these tables, including one
-- that never passes through that package.
--
-- ---------------------------------------------------------------------------
-- NO SELECT PRE-CHECK, DELIBERATELY
-- ---------------------------------------------------------------------------
--
-- All three tables FORCE row-level security on app.current_org_id, which binds
-- the table OWNER too. A `SELECT count(*) ... WHERE root <> 'organization'` from
-- the migration connection reads only the rows of the one organization its GUC
-- names - usually none - and would report zero whether or not a system-root row
-- exists. That is a check that cannot fail.
--
-- ADD CONSTRAINT validates EVERY existing row, and row-level security does not
-- apply to constraint validation. The ALTER is therefore the check with teeth,
-- and each one is wrapped so its failure names the table it found a row in.
--
-- ---------------------------------------------------------------------------
-- IF IT FAILS
-- ---------------------------------------------------------------------------
--
-- A deployment holding such a row stops here and NOTHING is changed: the file
-- is one transaction. The row is not deleted by this migration, because a row
-- nobody can account for is evidence and belongs to a person, not to a boot.
-- The error says how to find it and how to remove it after review; the
-- procedure is repeated in the down file's header.
--
-- ---------------------------------------------------------------------------
-- REVISIT WHEN
-- ---------------------------------------------------------------------------
--
-- Arm 2 of the signing-authority design - an operator publication under the
-- system root, bound to shipped detector records - is built. Its rows will need
-- these tables, with the authority that admitted them recorded beside them.
-- Widen the CHECK in that change, together with that authority, not before.
--
-- ---------------------------------------------------------------------------

BEGIN;

DO $$
BEGIN
    ALTER TABLE typed_policy_artifacts DROP CONSTRAINT IF EXISTS typed_policy_artifacts_root_chk;
    ALTER TABLE typed_policy_artifacts
        ADD CONSTRAINT typed_policy_artifacts_root_chk CHECK (root = 'organization');
EXCEPTION WHEN check_violation THEN
    RAISE EXCEPTION 'migration 178: typed_policy_artifacts holds at least one row whose root is not organization, and nothing was changed'
        USING ERRCODE = 'check_violation',
              DETAIL = 'A durable system-root artifact has no legitimate writer (#4047): the system root''s authority is the shipped corpus, which is signed per process and never stored.',
              HINT = 'As a role that bypasses row-level security, run: SELECT org_id, root, digest, document_id, key_id, admitted_at FROM typed_policy_artifacts WHERE root <> ''organization''. After review, remove the row as the table owner with triggers typed_policy_artifacts_no_update_delete disabled for that statement, then re-run migrations.';
END
$$;

DO $$
BEGIN
    ALTER TABLE typed_policy_activations DROP CONSTRAINT IF EXISTS typed_policy_activations_root_chk;
    ALTER TABLE typed_policy_activations
        ADD CONSTRAINT typed_policy_activations_root_chk CHECK (root = 'organization');
EXCEPTION WHEN check_violation THEN
    RAISE EXCEPTION 'migration 178: typed_policy_activations holds at least one row whose root is not organization, and nothing was changed'
        USING ERRCODE = 'check_violation',
              DETAIL = 'A durable system-root activation has no legitimate writer (#4047): the system root''s authority is the shipped corpus, which is signed per process and never stored.',
              HINT = 'As a role that bypasses row-level security, run: SELECT org_id, root, seq, digest, actor, activated_at FROM typed_policy_activations WHERE root <> ''organization''. After review, remove the row as the table owner with trigger typed_policy_activations_no_update_delete disabled for that statement, then re-run migrations.';
END
$$;

DO $$
BEGIN
    ALTER TABLE typed_policy_signing_keys DROP CONSTRAINT IF EXISTS typed_policy_signing_keys_root_chk;
    ALTER TABLE typed_policy_signing_keys
        ADD CONSTRAINT typed_policy_signing_keys_root_chk CHECK (root = 'organization');
EXCEPTION WHEN check_violation THEN
    RAISE EXCEPTION 'migration 178: typed_policy_signing_keys holds at least one row whose root is not organization, and nothing was changed'
        USING ERRCODE = 'check_violation',
              DETAIL = 'A durable signing key under the system root is authority granted by whoever inserted it (#4047): the system root''s authority is the shipped corpus, which is signed per process and never stored.',
              HINT = 'As a role that bypasses row-level security, run: SELECT org_id, root, key_id, authorized_by, authorized_at FROM typed_policy_signing_keys WHERE root <> ''organization''. After review, remove the row as the table owner with trigger typed_policy_signing_keys_revoke_only disabled for that statement, then re-run migrations.';
END
$$;

-- SELF-VERIFICATION before COMMIT: exactly three root constraints, each of
-- which admits the organization root and does not mention the system root.
DO $$
DECLARE
    found   INTEGER;
    wrong   TEXT;
BEGIN
    SELECT count(*),
           string_agg(conrelid::regclass::text || ': ' || pg_get_constraintdef(oid), '; ')
               FILTER (WHERE pg_get_constraintdef(oid) LIKE '%system%'
                          OR pg_get_constraintdef(oid) NOT LIKE '%organization%')
      INTO found, wrong
      FROM pg_constraint
     WHERE conname IN ('typed_policy_artifacts_root_chk',
                       'typed_policy_activations_root_chk',
                       'typed_policy_signing_keys_root_chk');
    IF found <> 3 THEN
        RAISE EXCEPTION 'migration 178 self-verification: expected 3 typed-authoring root constraints, found %', found;
    END IF;
    IF wrong IS NOT NULL THEN
        RAISE EXCEPTION 'migration 178 self-verification: a root constraint still admits another root: %', wrong;
    END IF;
END
$$;

COMMIT;
