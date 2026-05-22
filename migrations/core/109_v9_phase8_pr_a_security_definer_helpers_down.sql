-- Migration 109 down: drop the 5 SECURITY DEFINER helpers.
-- Idempotent via IF EXISTS.
--
-- Caveat: the up migration's callers (community_saas_register.go,
-- community_saas_recovery.go, db_auth.go, customer-portal/api/keys.go)
-- will fail with "function does not exist" until the binary is rolled
-- back to a pre-mig-109 image. Down migration ordering is therefore
--   1. flip binary back (or stop traffic)
--   2. run this down migration
-- — same constraint as mig 108 down.

BEGIN;

DROP FUNCTION IF EXISTS csaas_register_tenant(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ, VARCHAR);
DROP FUNCTION IF EXISTS csaas_register_touch(VARCHAR);
DROP FUNCTION IF EXISTS csaas_recovery_insert(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ, VARCHAR);
DROP FUNCTION IF EXISTS auth_insert_api_key(VARCHAR, VARCHAR, VARCHAR, VARCHAR, INTEGER, VARCHAR);
DROP FUNCTION IF EXISTS portal_insert_api_key(VARCHAR, VARCHAR, VARCHAR, VARCHAR, JSONB, TIMESTAMPTZ);

COMMIT;
