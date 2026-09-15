-- Migration 172 DOWN: restore write access to the legacy policy tables
-- Date: 2026-09-08
-- Purpose: Reverse migrations/core/172_legacy_policy_tables_read_only.sql by
--          re-granting INSERT, UPDATE and DELETE on static_policies and
--          dynamic_policies to the application roles.
-- Related: #3786, ADR-065 Phase 5
--
-- This is a REAL rollback rather than the no-op that core/170's and
-- enterprise/151's down migrations are. Those grant privileges that were
-- already held, so revoking on the way down could take away something another
-- migration granted; this one REMOVED privileges that core/098 had granted, so
-- putting them back is exactly what undoing it means.
--
-- WHAT THIS DOWN MIGRATION DOES NOT REVERSE, STATED SO THE "REAL ROLLBACK"
-- CLAIM ABOVE IS NOT READ WIDER THAN IT IS
--
-- The up migration does TWO things: it revokes privileges, and it re-creates
-- activate_integration() as SECURITY DEFINER with a pinned search_path, an
-- org predicate in the body, a prefix length floor, starts_with() instead of
-- LIKE, and EXECUTE revoked from PUBLIC. This file reverses the FIRST only.
--
-- That is deliberate, and it is the safe direction. Restoring the SECURITY
-- INVOKER definition would take the function back to a form whose UPDATE is
-- refused for both application roles the moment 172 is re-applied - and, more
-- to the point, would hand back a caller-supplied LIKE pattern and no org
-- predicate, which is the shape the up migration exists to have removed. A
-- rollback that reinstates a privilege escalation is not a rollback anyone
-- wants, and the hardened function is correct under both privilege postures:
-- it works when the grants are restored and it works when they are not.
--
-- So after this down migration the deployment has core/098's grants back AND a
-- hardened activate_integration(). That is a state the tree has never been in
-- before, and it is stated here rather than discovered.
--
-- TRUNCATE is deliberately NOT restored. core/098 granted
-- SELECT, INSERT, UPDATE, DELETE — never TRUNCATE — so re-granting it would
-- leave the database in a state migration 172 never found it in.
--
-- DOES THIS RESTORE MORE THAN THE TREE HAD?
--
-- The set below is core/098's, stated literally rather than derived from the
-- pre-172 state, which is only correct while nothing between 098 and 172
-- NARROWED it: an intervening revoke would make this rollback hand back more
-- than the deployment had before 172 ran.
--
-- Checked, and the answer is no. Exactly two migrations issue an executable
-- REVOKE naming an application role and reaching these tables (by name or
-- through ALL TABLES): core/098's own down, which is the wholesale role
-- teardown, and 172 itself. Three others look like they do and do not —
-- core/170_down and enterprise/151_down say "IT REVOKES NOTHING, AND THAT IS
-- THE WHOLE POINT" in a comment and repeat the word inside a RAISE NOTICE,
-- and community-saas/085 revokes from `community_saas_bridge_ro`, a read-only
-- role this rollback never touches.
--
-- That check does not stay true on its own, so it is enforced rather than
-- recorded: tests/regression-test-required/legacy_policy_write_surface_test.sh
-- fails on any new migration that revokes an application role's privileges
-- over these tables, and names this file as the thing that must then change.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_app_role') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON static_policies  TO axonflow_app_role;
        GRANT SELECT, INSERT, UPDATE, DELETE ON dynamic_policies TO axonflow_app_role;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_platform_admin') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON static_policies  TO axonflow_platform_admin;
        GRANT SELECT, INSERT, UPDATE, DELETE ON dynamic_policies TO axonflow_platform_admin;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- THE VIEW GRANTS ARE NOT THIS ROLLBACK'S
--
-- An earlier version of this file re-granted write on every view reaching a
-- legacy policy table, and dropped enforce_legacy_policy_read_only(). Both
-- moved to migrations/core/174, which now owns that function outright.
--
-- Leaving the DROP here would have made this rollback silently re-open #3905 on
-- any deployment that had taken 174: undoing a table revoke would also have
-- removed an unrelated tenant-isolation fix, with nothing in the diff of either
-- migration saying so. A teardown must not reach outside what its own up
-- migration created.
-- ---------------------------------------------------------------------------


DO $$
DECLARE
    r          TEXT;
    t          TEXT;
    confirmed  INTEGER := 0;
    roles_seen INTEGER := 0;
BEGIN
    FOREACH r IN ARRAY ARRAY['axonflow_app_role', 'axonflow_platform_admin'] LOOP
        CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r);
        roles_seen := roles_seen + 1;
        FOREACH t IN ARRAY ARRAY['static_policies', 'dynamic_policies'] LOOP
            IF NOT has_table_privilege(r, t, 'INSERT')
               OR NOT has_table_privilege(r, t, 'UPDATE')
               OR NOT has_table_privilege(r, t, 'DELETE')
               OR NOT has_table_privilege(r, t, 'SELECT') THEN
                RAISE EXCEPTION 'Migration 172 down failed: % does not hold SELECT/INSERT/UPDATE/DELETE on %', r, t;
            END IF;
            confirmed := confirmed + 1;
        END LOOP;
    END LOOP;

    IF roles_seen > 0 AND confirmed <> roles_seen * 2 THEN
        RAISE EXCEPTION 'Migration 172 down failed: % role(s) present but only % (role, table) pair(s) verified', roles_seen, confirmed;
    END IF;

    RAISE NOTICE 'Migration 172 down verified: write access restored on static_policies and dynamic_policies for % application role(s).', roles_seen;
END $$;

COMMIT;
