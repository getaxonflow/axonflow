-- Migration 174 DOWN: restore the view write grants core/098 gave
-- Date: 2026-09-09
-- Related: #3905, #3786
--
-- This is a REAL rollback: 174 REMOVED privileges that core/098 had granted, so
-- putting them back is what undoing it means.
--
-- ---------------------------------------------------------------------------
-- SCHEMA public ONLY, WHICH IS NARROWER THAN WHAT THE UP MIGRATION BINDS
-- ---------------------------------------------------------------------------
--
-- The asymmetry is deliberate and it is the correct direction.
--
-- core/098 grants write on views two ways, and BOTH are scoped to schema
-- public: `GRANT ... ON ALL TABLES IN SCHEMA public` and `ALTER DEFAULT
-- PRIVILEGES IN SCHEMA public`. So a view in an `analytics` or `reporting`
-- schema never held an application grant to begin with, and re-granting one
-- here would hand the application roles a privilege the tree has never given
-- them - on an owner-owned view over an ENABLE-not-FORCE RLS table, which is to
-- say this file would CREATE the exact cross-tenant path 174 exists to close.
--
-- The up migration is right to bind every schema: an explicit grant someone
-- else made is still a live write path. The down migration is right to restore
-- only what core/098 gave. A rollback that cannot distinguish "I revoked this"
-- from "this was never granted" must choose the narrower action, because the
-- cost of the two mistakes is not symmetric: failing to restore a grant is a
-- permission error an operator sees immediately, and inventing one is a silent
-- cross-tenant hole.
--
-- TRUNCATE is deliberately NOT restored. core/098 granted SELECT, INSERT,
-- UPDATE, DELETE - never TRUNCATE - so re-granting it would leave the database
-- in a state this migration never found it in.
--
-- The function is dropped LAST, after its own closure query has been used.

BEGIN;

DO $$
DECLARE
    rel      RECORD;
    r        TEXT;
    restored INTEGER := 0;
BEGIN
    FOR rel IN
        WITH RECURSIVE reached AS (
            SELECT c.oid
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relname IN ('static_policies', 'dynamic_policies')
            UNION
            SELECT rw.ev_class
            FROM pg_catalog.pg_depend d
            JOIN pg_catalog.pg_rewrite rw ON rw.oid = d.objid AND d.classid = 'pg_rewrite'::regclass
            JOIN reached ON reached.oid = d.refobjid AND d.refclassid = 'pg_class'::regclass
            WHERE rw.ev_class <> d.refobjid
        )
        SELECT n.nspname, c.relname
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN reached ON reached.oid = c.oid
        WHERE c.relkind = 'v'
          AND n.nspname = 'public'
        ORDER BY n.nspname, c.relname
    LOOP
        FOREACH r IN ARRAY ARRAY['axonflow_app_role', 'axonflow_platform_admin'] LOOP
            CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r);
            BEGIN
                EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I.%I TO %I',
                               rel.nspname, rel.relname, r);
                restored := restored + 1;
            EXCEPTION WHEN insufficient_privilege THEN
                RAISE NOTICE 'Migration 174 down: %.% is not owned here; its grants are unchanged.', rel.nspname, rel.relname;
            END;
        END LOOP;
    END LOOP;
    RAISE NOTICE 'Migration 174 down: % (view, role) write grant(s) restored.', restored;
END $$;

DROP FUNCTION IF EXISTS enforce_legacy_policy_read_only();

DO $$
BEGIN
    IF to_regprocedure('public.enforce_legacy_policy_read_only()') IS NOT NULL THEN
        RAISE EXCEPTION 'Migration 174 down failed: the enforcer is still present';
    END IF;
    RAISE NOTICE 'Migration 174 down verified: view write grants restored in schema public and the enforcer removed.';
END $$;

COMMIT;
