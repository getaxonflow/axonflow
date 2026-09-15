-- Migration 171 DOWN: remove the principal_admissions ledger and the
--                     node_leases concurrency table (#3593)
-- Date: 2026-09-08
--
-- WHAT A ROLLBACK MEANS HERE. The ledger is the memory of which principals an
-- organization has admitted. Dropping it forgets every admission, so on the
-- next forward apply every principal is "new" again and the count restarts
-- from zero. That is the safe direction - nobody already admitted is refused
-- by a rollback; the limit is simply re-measured from scratch - and the row
-- counts are reported so the operator knows what was forgotten. Dropping
-- node_leases forgets every lease; each node re-leases on its next heartbeat.
--
-- THE COUNTS ARE TAKEN UNDER `SET LOCAL row_security = off`, INSIDE A
-- BEGIN/EXCEPTION ARM, AND REPORTED AS UNAVAILABLE WHEN THAT FAILS.
-- Both tables are FORCE-RLS with an org-isolation predicate on
-- app.current_org_id. In a rollback session that GUC is unset, the predicate
-- is NULL for every row, and a plain count therefore returns ZERO however many
-- rows exist - printing a reassuring zero while the rollback discards them.
-- `SET LOCAL row_security = off` itself SUCCEEDS for a NOBYPASSRLS role; it is
-- the subsequent count that raises 42501, which is why the handler is around
-- the count and why it reports the number as unavailable rather than inventing
-- a zero. Shape copied from
-- migrations/enterprise/150_identity_org_settings_decision_shadow_down.sql;
-- platform/agent/migration_rls_grant_census_test.go requires it of any down
-- migration that counts a FORCE-RLS table.
--
-- The triggers refuse DELETE and TRUNCATE by design; DROP TABLE is not a
-- row-level operation and is not bound by them, so the drop needs no trigger
-- dance.

BEGIN;

DO $$
DECLARE
    rows_total bigint  := 0;
    orgs       bigint  := 0;
    leases     bigint  := 0;
    counted    boolean := false;
BEGIN
    IF to_regclass('principal_admissions') IS NULL AND to_regclass('node_leases') IS NULL THEN
        RAISE NOTICE 'migration 171 down: principal_admissions / node_leases do not exist; nothing to remove.';
        RETURN;
    END IF;

    BEGIN
        SET LOCAL row_security = off;
        IF to_regclass('principal_admissions') IS NOT NULL THEN
            SELECT count(*), count(DISTINCT org_id) INTO rows_total, orgs FROM principal_admissions;
        END IF;
        IF to_regclass('node_leases') IS NOT NULL THEN
            SELECT count(*) INTO leases FROM node_leases;
        END IF;
        counted := true;
    EXCEPTION WHEN OTHERS THEN
        counted := false;
    END;
    SET LOCAL row_security = on;

    IF to_regclass('principal_admissions') IS NOT NULL THEN
        DROP POLICY IF EXISTS principal_admissions_org_isolation ON principal_admissions;
        DROP TRIGGER IF EXISTS principal_admissions_no_update_delete ON principal_admissions;
        DROP TRIGGER IF EXISTS principal_admissions_no_truncate ON principal_admissions;
        DROP TABLE principal_admissions;
    END IF;
    IF to_regclass('node_leases') IS NOT NULL THEN
        DROP POLICY IF EXISTS node_leases_org_isolation ON node_leases;
        DROP TABLE node_leases;
    END IF;

    IF counted THEN
        RAISE NOTICE 'migration 171 down: dropped principal_admissions (% admission row(s) across % organization(s) forgotten; the next forward apply re-measures every limit from zero) and node_leases (% lease row(s); every node re-leases on its next heartbeat)',
            rows_total, orgs, leases;
    ELSE
        RAISE NOTICE 'migration 171 down: dropped principal_admissions and node_leases. THE ROWS COULD NOT BE COUNTED: this role cannot disable row-level security on them and migration 171 sets FORCE RLS, so any count taken here would have been 0 regardless of the truth. Re-run as a BYPASSRLS role to see what was discarded.';
    END IF;
END $$;

DROP FUNCTION IF EXISTS principal_admissions_append_only();

COMMIT;
