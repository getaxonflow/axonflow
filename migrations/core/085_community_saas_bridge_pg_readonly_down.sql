-- Down migration for 085: drop the community_saas_bridge_ro role.
-- Date: 2026-05-08
-- Context: paired with 085_community_saas_bridge_pg_readonly.sql (#2011 phase A1).
--
-- Revoking grants from a role and then dropping it requires the operator
-- to first verify no live database session is connected as that role,
-- and that no Lambda is actively running queries with it. The community-
-- saas-bridge stack must be deleted (or the Lambda's PG_USER overridden)
-- BEFORE running this down migration; otherwise live invocations 500
-- with "permission denied" until the role re-applies.

REVOKE ALL PRIVILEGES ON community_saas_registrations FROM community_saas_bridge_ro;
REVOKE USAGE ON SCHEMA public FROM community_saas_bridge_ro;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'community_saas_bridge_ro') THEN
        DROP ROLE community_saas_bridge_ro;
        RAISE NOTICE 'Migration 085 DOWN: community_saas_bridge_ro role dropped';
    ELSE
        RAISE NOTICE 'Migration 085 DOWN: community_saas_bridge_ro role already absent (idempotent re-run)';
    END IF;
END $$;
