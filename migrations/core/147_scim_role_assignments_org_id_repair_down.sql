-- Migration 147 DOWN: no-op — the org_id repair is deliberately NOT reverted
--                       (#2964)
-- Date: 2026-07-17
--
-- Migration 147 forward re-keyed SCIM-written role_assignments rows from an
-- addressing tenant id to the REAL org (and removed the stale tenant-keyed
-- originals). It added NO schema objects — only data repair — so there is
-- nothing structural to drop.
--
-- It deliberately does NOT revert the data, for the same reasons as mig 145:
--
--   * Reverting is not distinguishable. After the repair, a real-org
--     role_assignments row written by the FIXED SCIM plane is byte-for-byte
--     identical to one the repair produced. Any revert predicate (org_id maps
--     to a tenants.org_id) would re-point HEALTHY rows the repair never touched
--     — including every assignment a single-tenant org ever made — back onto an
--     addressing tenant, MANUFACTURING #2964 on a database that never had it:
--     the fleet resolver, scoped on the real org, would then miss them and drop
--     those developers to least-privilege.
--
--   * It would not be self-healing. The agent's migration runner applies only
--     `*.sql`, never `*_down.sql` (migration_helpers.go) — a down is
--     operator-run — and does not delete the schema_migrations row. A
--     roll-forward would treat 147 as already applied and SKIP it, leaving the
--     mis-key in place with no automatic repair.
--
-- The forward repair is idempotent and safe to re-run, so roll-forward is the
-- supported recovery path. If you must restore the pre-147 (tenant-keyed) data
-- shape, do it by hand and ONLY for the rows you mean to, while running pre-147
-- application code (on 147+ the fixed SCIM plane writes the real org and any
-- hand-revert reintroduces #2964).

BEGIN;

DO $$
BEGIN
    RAISE NOTICE 'Migration 147 down: no-op. role_assignments.org_id deliberately left on the real org - see this file''s header before re-pointing it by hand.';
END $$;

COMMIT;
