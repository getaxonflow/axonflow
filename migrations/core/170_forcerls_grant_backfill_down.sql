-- Migration 170 Down: deliberately a NO-OP (#3636)
--
-- ════════════════════════════════════════════════════════════════════════════
-- IT REVOKES NOTHING, AND THAT IS THE WHOLE POINT
-- ════════════════════════════════════════════════════════════════════════════
--
-- An earlier version of this file ran REVOKE. That was WRONG, and wrong in the
-- direction that breaks a healthy deployment.
--
-- A GRANT is not reference-counted. core/098's
-- `GRANT ... ON ALL TABLES IN SCHEMA public TO axonflow_app_role` and the up
-- migration's per-table grant are THE SAME PRIVILEGE, not two of them: the up
-- migration re-states a privilege the role already holds almost everywhere.
-- Revoking once therefore removes the access core/098 created, on every
-- deployment where the single-owner path applied - which a fresh chain shows is
-- all of them: 125 tables, 26 under FORCE RLS, zero lacking the app role's
-- SELECT or INSERT before this migration runs at all.
--
-- So the rollback of a re-statement cannot be a revocation. The earlier version
-- would have left axonflow_app_role unable to read organizations, tenants,
-- connectors, audit_archive and the rest on every house-shaped stack, and its
-- "nothing was lost" branch could never print, because there is nothing for the
-- privilege to fall back to.
--
-- Rolling back an idempotent re-statement of an existing privilege correctly
-- means doing nothing. An operator who genuinely wants to remove an
-- application role's access to a table is doing something this migration never
-- did and must do it deliberately, naming the table, with the consequence in
-- front of them - not by rolling back a backfill.
--
-- The NOTICE says so rather than the file being silent, because a down
-- migration that appears to do nothing and explains nothing is one an operator
-- re-runs, wraps or edits.

BEGIN;

DO $$
BEGIN
    RAISE NOTICE 'migration 170 down: intentionally a no-op. The up migration RE-STATED privileges core/098 already grants (GRANT ... ON ALL TABLES), and a GRANT is not reference-counted - so revoking here would remove the access core/098 created, not the access this migration added. To remove an application role''s access to a specific table, do it deliberately: REVOKE SELECT, INSERT, UPDATE, DELETE ON <table> FROM <role>;';
END
$$;

COMMIT;
