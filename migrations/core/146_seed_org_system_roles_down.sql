-- Migration 146 DOWN: remove the system-role seeder + trigger (#2963)
-- Date: 2026-07-17
--
-- Drops the organizations AFTER INSERT trigger and both seeder functions.
--
-- It deliberately does NOT delete the seeded custom_roles rows. They are
-- ordinary role definitions; a SCIM group->role mapping or a role_assignment
-- may reference them, so deleting them could orphan or cascade live mappings
-- and silently drop developers to least-privilege — a worse outcome than
-- leaving inert rows that pre-#2963 code simply ignores. If a full data
-- rollback is genuinely wanted, delete the is_system seed rows by hand after
-- confirming nothing maps to them:
--
--   DELETE FROM custom_roles
--    WHERE created_by = 'system'
--      AND name IN ('admin','owner','policy_admin','developer','member','viewer')
--      AND NOT EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.role_id = custom_roles.id);

BEGIN;

DROP TRIGGER IF EXISTS seed_org_system_roles ON organizations;
DROP FUNCTION IF EXISTS trg_ensure_org_system_roles();
DROP FUNCTION IF EXISTS ensure_org_system_roles(VARCHAR);

DO $$
BEGIN
    RAISE NOTICE 'Migration 146 down: dropped seed_org_system_roles trigger + seeder functions. Seeded role rows left in place - see header before deleting.';
END $$;

COMMIT;
