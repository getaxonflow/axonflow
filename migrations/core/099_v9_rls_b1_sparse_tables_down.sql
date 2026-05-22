-- Migration 099 DOWN: reverse FORCE RLS on sparse audit/config tables
-- Context: reverses 099_v9_rls_b1_sparse_tables.sql
--
-- After this runs, the three sparse tables behave the same as they did pre-099:
-- RLS is enabled and policies exist (where they pre-existed in 018/019), but
-- the table owner / RDS master bypasses them.
--
-- For audit_archive (which had RLS first-enabled in 099), this DOWN also
-- disables RLS and drops the policy — restoring exact pre-099 byte-equal state.

BEGIN;

-- Drop FORCE first (NO FORCE) — order matters to be symmetric with the up.
ALTER TABLE deployment_upgrades NO FORCE ROW LEVEL SECURITY;
ALTER TABLE saml_configurations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_archive       NO FORCE ROW LEVEL SECURITY;

-- audit_archive was first-enabled in 099 — reverse that. We do NOT reverse the
-- ENABLE on deployment_upgrades + saml_configurations because they were already
-- enabled before 099 (by 018/019).
ALTER TABLE audit_archive DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_archive_org_isolation ON audit_archive;

-- We deliberately do NOT drop the deployment_upgrades_org_isolation /
-- saml_configurations tenant_isolation_* policies: those were created (or
-- re-asserted to a deterministic shape) by migration 099, but they're harmless
-- without FORCE RLS. Dropping them would leave 018/019's optional-create paths
-- in an inconsistent state.

COMMIT;
