-- Migration 145 DOWN: drop the pre-auth org lookup (#2960)
-- Date: 2026-07-17
--
-- Drops the SECURITY DEFINER helper the up migration added.
--
-- It deliberately does NOT revert the org_id repair. That is not an oversight —
-- reverting it is unsafe in both directions:
--
--   * The only predicate available to a revert is tenant_id = '__platform__'
--     (the up migration leaves nothing to distinguish a row it repaired from a
--     row the FIXED portal wrote correctly afterwards). So a revert would
--     re-point healthy rows the up migration never touched, MANUFACTURING #2960
--     on a database that never had it: org_id back at the sentinel means the
--     fleet OIDC verifier resolves nothing and every per-user token is rejected
--     fail-closed.
--
--   * It would not be self-healing. The agent's migration runner only applies
--     `*.sql`, never `*_down.sql` (migration_helpers.go) — a down is
--     operator-run — and this file does not delete the schema_migrations row.
--     So a roll-forward would consider 145 already applied and SKIP it, leaving
--     the sentinel in place with no automatic repair. The damage would be
--     silent and permanent.
--
-- The cost of not reverting is far smaller and is recoverable: application code
-- rolled back to pre-145 scopes app.current_org_id on the collapsed tenant id,
-- so under FORCE RLS the portal's SSO settings page reads/writes nothing and
-- reports "not configured" for an in-vpc deployment. SSO LOGIN is unaffected —
-- the pre-145 SAML path resolves by tenant_id, and portal_check_sso_availability
-- resolves by org_id, which the repair made correct. Rolling forward restores
-- the settings page with no data work.
--
-- If you genuinely need the pre-145 data shape — a permanent rollback of both
-- code and data — re-point the rows by hand, and only the ones you mean to:
--
--   UPDATE sso_configurations SET org_id = '__platform__' WHERE tenant_id = '__platform__';
--   -- and the same for sso_sessions / sso_login_attempts.
--
-- Do that ONLY while running pre-145 code: on 145+ it reintroduces #2960.

BEGIN;

DROP FUNCTION IF EXISTS sso_config_org_for_tenant(VARCHAR);

DO $$
BEGIN
    RAISE NOTICE 'Migration 145 down: dropped sso_config_org_for_tenant. sso_*.org_id deliberately left on the real org - see this file''s header before re-pointing it by hand.';
END $$;

COMMIT;
