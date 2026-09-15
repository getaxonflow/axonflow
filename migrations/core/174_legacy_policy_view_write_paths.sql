-- Migration 174: close the auto-updatable VIEW write paths into the legacy policy tables
-- Date: 2026-09-09
-- Purpose: Stop an application role reaching ANOTHER organization's
--          static_policies / dynamic_policies rows through a view.
-- Related: #3905 (the measurement), #3786, v11 decision D1.
--
-- EDITION: COMMUNITY (mirrored). Every migration that produces the condition -
-- core/014, core/018, core/098 - is a core migration and applies on every
-- deployment mode, so the exposure is not edition-specific and neither is the
-- fix.
--
-- ---------------------------------------------------------------------------
-- WHAT THIS CLOSES, MEASURED RATHER THAN REASONED
-- ---------------------------------------------------------------------------
--
-- `eu_ai_act_compliance_summary` (core/014, recreated by core/127) is a
-- single-table view over static_policies with no join, aggregate, DISTINCT,
-- GROUP BY, LIMIT or set operation, which makes it AUTO-UPDATABLE: an UPDATE or
-- DELETE against it is rewritten into a write of the underlying table, executed
-- with the VIEW OWNER's privileges.
--
-- static_policies is ENABLE ROW LEVEL SECURITY, not FORCE (core/018), so the
-- owner is not bound by core/018's tenant_isolation_* policies. And core/098
-- grants the application roles write on views twice over: `GRANT ... ON ALL
-- TABLES IN SCHEMA public` includes views, and `ALTER DEFAULT PRIVILEGES`
-- grants the same set to every view created afterwards.
--
-- Measured on a schema at core/171 - the state every deployment is in today -
-- as axonflow_app_role scoped to one organization, against a row planted in
-- another:
--
--     app role sees the other org's row DIRECTLY:      0 rows
--     app role sees it THROUGH THE VIEW:               1 row
--     DIRECT cross-org UPDATE:   no error, row UNCHANGED   <- RLS holds
--     UPDATE THROUGH THE VIEW:   no error, row CHANGED     <- RLS bypassed
--     DELETE THROUGH THE VIEW:   no error, row GONE
--
-- THE CONTRAST IS THE FINDING, AND IT DECIDES WHAT THIS MIGRATION MUST DO.
-- The application role ALREADY HOLDS `UPDATE` on static_policies at 171; the
-- direct write is not refused, it simply matches nothing, because RLS scopes it
-- to the caller's own organization. Routed through the view, the identical
-- statement reaches another organization's row and lands.
--
-- So this is not a write-privilege escalation. It is a TENANT-ISOLATION
-- bypass - and it is invisible to any check that asks "may this role write this
-- table", because the honest answer is yes.
--
-- ---------------------------------------------------------------------------
-- WHY A FUNCTION CALLED AFTER EVERY MIGRATION, AND NOT A REVOKE HERE
-- ---------------------------------------------------------------------------
--
-- A literal REVOKE in this file binds only the views that exist when it runs.
-- There are FIVE AUTO-UPDATABLE views over static_policies and FOUR of them are
-- created by the industry verticals, which are numbered 200+ *specifically so
-- that they run after core and enterprise* (platform/agent/migration_helpers.go). On a
-- fresh in-vpc-banking or travel deployment they are therefore created AFTER
-- this migration, and core/098's ALTER DEFAULT PRIVILEGES grants each one write
-- as it is created. A revoke here would be correct on every upgrade and wrong
-- on every fresh install of the deployment modes carrying the most policy
-- surface.
--
-- THE COUNT IS FIVE, AND IT WAS SEVEN UNTIL IT WAS DRIVEN. An earlier version
-- of this reasoning counted every view whose definition selects from
-- static_policies. Three of those carry a join, an aggregate or a GROUP BY -
-- sebi_audit_retention_status and mas_audit_retention_status (LEFT JOIN
-- policy_violations + COUNT + GROUP BY) and mas_feat_pillar_coverage (COUNT(*)
-- + GROUP BY) - which makes them NOT auto-updatable, so no write can be routed
-- through them and they are not in this class at all. Shape inference read
-- "selects from static_policies" as "is a write path"; running it against a
-- real industry chain is what corrected the number.
--
-- Fixing it in the industry files is not available either: a deployed migration
-- is immutable in this repository (technical-docs/MIGRATION_SYSTEM_COMPLETE_
-- GUIDE.md section 5), and a per-vertical migration would still be silent about
-- the next vertical.
--
-- So the invariant - "no relation confers on an application role a write that
-- reaches a legacy policy table" - is enforced where it can be true: as a
-- function over the live catalogue, called after ALL DDL has run
-- (platform/agent/run.go, after the migration loop). It is idempotent, it takes
-- the transitive closure so a view over a view is bound, and it raises rather
-- than warns.
--
-- ---------------------------------------------------------------------------
-- WHAT THIS DELIBERATELY DOES NOT DO
-- ---------------------------------------------------------------------------
--
-- It does NOT revoke write on static_policies or dynamic_policies themselves.
-- That is #3786 / PR #3880's scope and it is a much larger change, because the
-- tables have live writers - including activate_integration(), which writes
-- static_policies on every check_policy request and has to be re-homed first.
-- This migration is deliberately separable from that decision: the cross-tenant
-- bypass is live today and should not wait on it.
--
-- It does NOT add FORCE ROW LEVEL SECURITY to the two tables. That would bind
-- the owner and close this whole class at the source rather than per-relation,
-- and it is the better long-term shape - but the seed migrations run as the
-- owner, so it is a migration-chain change with its own review. Named as a
-- direction; not taken here.
--
-- REVISIT WHEN static_policies gains FORCE ROW LEVEL SECURITY: at that point an
-- owner-owned view is bound by the org predicate too, this function becomes
-- redundant for the isolation property, and it should be re-argued rather than
-- carried forward out of habit.

BEGIN;

-- A PRECONDITION, not a summary: this migration is about relations reaching
-- these two tables, and a closure over tables that do not exist is empty.
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['static_policies', 'dynamic_policies'] LOOP
        IF to_regclass(t) IS NULL THEN
            RAISE EXCEPTION 'Migration 174 failed: % does not exist; this migration is ordered after the seeds that create it', t;
        END IF;
    END LOOP;
END $$;

CREATE OR REPLACE FUNCTION enforce_legacy_policy_read_only()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    rel     RECORD;
    r       TEXT;
    held    BOOLEAN;
    revoked INTEGER := 0;
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
            JOIN pg_catalog.pg_rewrite rw
              ON rw.oid = d.objid
             AND d.classid = 'pg_rewrite'::regclass
            JOIN reached
              ON reached.oid = d.refobjid
             AND d.refclassid = 'pg_class'::regclass
            WHERE rw.ev_class <> d.refobjid
        )
        -- SCHEMA-QUALIFIED, AND TEMPORARY SCHEMAS EXCLUDED. Both halves matter.
        --
        -- Revoking by BARE NAME resolves the identifier against this function's
        -- search_path rather than the schema the relation is actually in. Three
        -- measured consequences, all fatal because the caller treats a failure
        -- as fatal: a TEMP view over static_policies held by any OTHER session -
        -- an operator's psql, a BI tool - made this raise `relation "..." does
        -- not exist`; a view in a non-public schema did the same permanently;
        -- and where a name existed in both schemas the REVOKE landed on the
        -- WRONG relation.
        --
        -- A temporary view is EXCLUDED rather than bound, and that is a claim
        -- about reach: a view's writes execute with the VIEW OWNER's
        -- privileges, so a temp view created by an application role is owned by
        -- that role and buys it nothing it does not already have. A permanent
        -- view in any other schema IS a genuine bypass and IS bound.
        SELECT c.oid, n.nspname, c.relname
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN reached ON reached.oid = c.oid
        WHERE c.relkind = 'v'
          AND n.nspname NOT LIKE 'pg\_temp%'
          AND n.nspname NOT LIKE 'pg\_toast%'
        ORDER BY n.nspname, c.relname
    LOOP
        FOREACH r IN ARRAY ARRAY['axonflow_app_role', 'axonflow_platform_admin'] LOOP
            CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r);

            -- Count what is actually REVOKED, not what is visited, so a no-op
            -- restart does not print the same number as a fresh industry
            -- deployment that really closed fourteen grants.
            held := has_table_privilege(r, rel.oid, 'INSERT')
                 OR has_table_privilege(r, rel.oid, 'UPDATE')
                 OR has_table_privilege(r, rel.oid, 'DELETE')
                 OR has_table_privilege(r, rel.oid, 'TRUNCATE')
                 OR has_any_column_privilege(r, rel.oid, 'INSERT')
                 OR has_any_column_privilege(r, rel.oid, 'UPDATE');

            -- A relation this function does not own cannot be revoked by it.
            -- Swallowing that is correct only because the verification below
            -- then decides: a foreign-owned view already closed is fine, and one
            -- that is OPEN raises - the invariant genuinely cannot be
            -- established and the caller must not pretend otherwise.
            BEGIN
                EXECUTE format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON %I.%I FROM %I',
                               rel.nspname, rel.relname, r);
            EXCEPTION WHEN insufficient_privilege THEN
                NULL;
            END;

            IF has_table_privilege(r, rel.oid, 'INSERT')
               OR has_table_privilege(r, rel.oid, 'UPDATE')
               OR has_table_privilege(r, rel.oid, 'DELETE')
               OR has_table_privilege(r, rel.oid, 'TRUNCATE')
               OR has_any_column_privilege(r, rel.oid, 'INSERT')
               OR has_any_column_privilege(r, rel.oid, 'UPDATE') THEN
                RAISE EXCEPTION
                    'enforce_legacy_policy_read_only: % still holds a write on view %.%, which reaches a legacy policy table',
                    r, rel.nspname, rel.relname
                    USING ERRCODE = 'insufficient_privilege';
            END IF;
            IF held THEN
                revoked := revoked + 1;
            END IF;
        END LOOP;
    END LOOP;
    RETURN revoked;
END $$;

-- SECURITY DEFINER because it REVOKEs, which only the object owner may do, and
-- the boot-time caller may be connected as something else. That makes the
-- hardening below mandatory rather than hygiene: without it any role could call
-- an owner-privileged REVOKE loop.
REVOKE EXECUTE ON FUNCTION enforce_legacy_policy_read_only() FROM PUBLIC;

-- and NO role is granted it back. The only caller is the boot path, on the
-- migration connection, which is the owner. Granting an application role the
-- ability to run an owner-privileged REVOKE loop would be handing out the
-- authority this migration exists to take away.

-- Bind the closure that exists right now. The boot-time call re-runs it after
-- the industry migrations have added theirs; running it here as well means an
-- upgrade is correct even under an older binary that does not make the call.
DO $$
DECLARE
    n INTEGER;
BEGIN
    SELECT enforce_legacy_policy_read_only() INTO n;
    RAISE NOTICE 'Migration 174: % (view, role) write grant(s) revoked on views reaching a legacy policy table.', n;
END $$;

-- ---------------------------------------------------------------------------
-- Self-verification BEFORE COMMIT
--
-- Asserted over the closure rather than over a list of view names, because a
-- literal list is a list of the views that existed on the day it was written -
-- and four of the five are added by migrations that have not run yet.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    rel      RECORD;
    r        TEXT;
    checked  INTEGER := 0;
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
        SELECT c.oid, n.nspname, c.relname
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN reached ON reached.oid = c.oid
        WHERE c.relkind = 'v'
          AND n.nspname NOT LIKE 'pg\_temp%'
          AND n.nspname NOT LIKE 'pg\_toast%'
    LOOP
        FOREACH r IN ARRAY ARRAY['axonflow_app_role', 'axonflow_platform_admin'] LOOP
            CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r);
            IF has_table_privilege(r, rel.oid, 'INSERT')
               OR has_table_privilege(r, rel.oid, 'UPDATE')
               OR has_table_privilege(r, rel.oid, 'DELETE')
               OR has_table_privilege(r, rel.oid, 'TRUNCATE')
               OR has_any_column_privilege(r, rel.oid, 'INSERT')
               OR has_any_column_privilege(r, rel.oid, 'UPDATE') THEN
                RAISE EXCEPTION 'Migration 174 failed: % can still write %.%', r, rel.nspname, rel.relname;
            END IF;
            checked := checked + 1;
        END LOOP;
    END LOOP;

    -- READS MUST SURVIVE. ADR-065 Phase 2 keeps the legacy evaluator as the
    -- per-plane shadow comparator, and this migration must not narrow SELECT on
    -- the tables it is protecting - a comparator that cannot read its own
    -- substrate compares nothing.
    FOREACH r IN ARRAY ARRAY['axonflow_app_role', 'axonflow_platform_admin'] LOOP
        CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r);
        IF NOT has_table_privilege(r, 'static_policies', 'SELECT')
           OR NOT has_table_privilege(r, 'dynamic_policies', 'SELECT') THEN
            RAISE EXCEPTION 'Migration 174 failed: % lost SELECT on a legacy policy table, which breaks the ADR-065 shadow comparator', r;
        END IF;
    END LOOP;

    RAISE NOTICE 'Migration 174 verified: % (view, role) pair(s) confer no write reaching a legacy policy table; reads intact.', checked;
END $$;

COMMIT;
