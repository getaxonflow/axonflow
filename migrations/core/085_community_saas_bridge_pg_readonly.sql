-- Migration 085: Community-SaaS bridge read-only Postgres role
-- Date: 2026-05-08
-- Context: Issue #2011 phase A1 — community-saas-bridge Lambda needs to
-- read community_saas_registrations to discover active tenants. Per the
-- A1 brief privacy + least-privilege requirements, the bridge connects
-- with a dedicated role that has SELECT-only access to a single table
-- and zero write capability anywhere.
--
-- Provides:
--   community_saas_bridge_ro — Postgres role; SELECT only on
--     community_saas_registrations. NO insert/update/delete on any
--     table. Operator sets the password out-of-band via:
--       ALTER ROLE community_saas_bridge_ro WITH PASSWORD '<random>';
--     and stores the password in AWS Secrets Manager at the ARN passed
--     to the bridge CFN stack as PGSecretARN.
--
-- Privacy boundary: the bridge SELECTs tenant_id + last_seen_at only
-- (see ee/platform/community-saas-bridge/pkg/bridge/tenants.go for the
-- exact query). The role's column-level grants restrict that to those
-- two columns at the DB layer as well — defense in depth.
--
-- Depends on: 068_community_saas_registrations (the table this role reads).

-- Create the role with NOLOGIN initially. Operator runs
--   ALTER ROLE community_saas_bridge_ro WITH LOGIN PASSWORD '<random>';
-- after the migration applies, then stores the password in Secrets
-- Manager. Splitting role-creation (deterministic migration) from
-- password-set (stochastic, secret-manager-only) keeps no plaintext
-- password ever in version control.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'community_saas_bridge_ro') THEN
        CREATE ROLE community_saas_bridge_ro NOLOGIN;
        RAISE NOTICE 'Migration 085: community_saas_bridge_ro role created (NOLOGIN — operator must set password + LOGIN out-of-band)';
    ELSE
        RAISE NOTICE 'Migration 085: community_saas_bridge_ro role already exists (idempotent re-run)';
    END IF;
END $$;

-- Grant USAGE on the schema so the role can resolve relation names.
-- Without this, even SELECT grants fail with "permission denied for schema".
GRANT USAGE ON SCHEMA public TO community_saas_bridge_ro;

-- Grant SELECT only on the two columns the bridge actually queries.
-- Defense in depth: even if the bridge code drifts and tries to read
-- secret_hash or claimed_by_email, the DB layer rejects.
GRANT SELECT (tenant_id, last_seen_at) ON community_saas_registrations TO community_saas_bridge_ro;

-- Explicitly REVOKE any default-grant write capability. Postgres default
-- new-role privileges are limited but this makes the intent explicit and
-- catches the case of a future migration accidentally running
-- GRANT ALL ON ALL TABLES IN SCHEMA public TO public.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON community_saas_registrations FROM community_saas_bridge_ro;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM community_saas_bridge_ro;

DO $$
BEGIN
    RAISE NOTICE 'Migration 085: community_saas_bridge_ro role provisioned with SELECT(tenant_id, last_seen_at) on community_saas_registrations only';
    RAISE NOTICE 'Operator next steps:';
    RAISE NOTICE '  1. ALTER ROLE community_saas_bridge_ro WITH LOGIN PASSWORD ''<generate-random-32-chars>'';';
    RAISE NOTICE '  2. aws secretsmanager put-secret-value --secret-id <PGSecretARN> --secret-string ''{"password":"<same-password>"}''';
    RAISE NOTICE '  3. Verify: psql --user community_saas_bridge_ro --command "SELECT count(*) FROM community_saas_registrations" should return a count; "INSERT" should fail with permission denied.';
END $$;
