-- Rollback for migration 103: FORCE RLS on identity tables
-- Date: 2026-05-21
-- Context: Pairs migration 103_v9_rls_b9_identity_tables.sql.
--
-- Strategy: drop the migration 103 policy + NO FORCE. Leave ENABLE RLS intact
-- because (a) migration 018 already ENABLEd RLS on organizations, and (b)
-- ENABLE without FORCE is inert under the table-owner / RDS master
-- connection that early v8.x deployments use, so rolling back ENABLE would be
-- behavior-change beyond what FORCE introduced.
--
-- For organizations this is byte-clean: migration 018 already had RLS
-- ENABLED, so leaving ENABLE in place restores the pre-103 state.
--
-- For tenants this DOES leave RLS enabled even though 018 didn't enable it.
-- Under `AXONFLOW_DB_USE_APP_ROLE=false` (master connection), RLS-enabled
-- tables behave identically to RLS-disabled tables (table-owner bypass) so
-- the down's behavior matches pre-103.
--
-- **CAVEAT** when running with `AXONFLOW_DB_USE_APP_ROLE=true`: under
-- `axonflow_app_role` (NOBYPASSRLS per migration 098), RLS-enabled tables
-- with zero policies default-deny. After this rollback runs on tenants,
-- the table has RLS ENABLED but no policies (we just DROPed the only one),
-- so app_role sees ZERO rows from tenants. If your env has flipped
-- `AXONFLOW_DB_USE_APP_ROLE=true`, ALSO run:
--
--     ALTER TABLE tenants DISABLE ROW LEVEL SECURITY;
--
-- after this rollback to restore app_role visibility on tenants. (Or run
-- this rollback only AFTER flipping `AXONFLOW_DB_USE_APP_ROLE=false`.)
--
-- Re-running 103 after this rollback is safe: ENABLE/FORCE are idempotent
-- and DROP POLICY IF EXISTS + CREATE POLICY handles the policy resurrect.

ALTER TABLE organizations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenants       NO FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS organizations_org_id_isolation ON organizations;
DROP POLICY IF EXISTS tenants_org_id_isolation ON tenants;

-- Note: leaving ENABLE on both tables intentionally (see header).
