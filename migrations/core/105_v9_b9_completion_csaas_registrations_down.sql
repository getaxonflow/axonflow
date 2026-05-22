-- Rollback for migration 105: community_saas_registrations FORCE RLS +
-- SECURITY DEFINER auth-lookup helper
--
-- WARNING: undoing FORCE alone is fine for app_role connections (they will
-- see all rows again because policy isn't FORCEd but ENABLE remains, and
-- app_role is NOBYPASSRLS). Undoing the helper while FORCE remains active
-- breaks validateCommunityRegistration — ONLY run this rollback in
-- coordination with rolling the table back to non-FORCE.

BEGIN;

ALTER TABLE community_saas_registrations NO FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS community_saas_registrations_org_id_isolation
    ON community_saas_registrations;

-- Do NOT disable RLS — other migrations may have policies that depend on it.

DROP FUNCTION IF EXISTS csaas_auth_lookup(VARCHAR);

COMMIT;
