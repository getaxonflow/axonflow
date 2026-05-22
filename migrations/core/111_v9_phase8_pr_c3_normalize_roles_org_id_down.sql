-- Migration 111 DOWN: restore custom_roles + role_assignments tenant_id column
-- Reverses mig 111 forward: rename org_id back to tenant_id on both tables,
-- restore the legacy constraint/index names, drop the canonical policy + recreate
-- the legacy USING-only policy shape.

BEGIN;

-- ============================================================================
-- Restore RLS policies first so they're not pointed at a column that's about
-- to be renamed. DROP IF EXISTS handles both names for re-run safety.
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'custom_roles') THEN
        DROP POLICY IF EXISTS custom_roles_tenant_isolation ON custom_roles;
        DROP POLICY IF EXISTS custom_roles_org_id_isolation ON custom_roles;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'role_assignments') THEN
        DROP POLICY IF EXISTS role_assignments_tenant_isolation ON role_assignments;
        DROP POLICY IF EXISTS role_assignments_org_id_isolation ON role_assignments;
    END IF;
END
$$;

-- ============================================================================
-- Rename org_id back to tenant_id on both tables
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'custom_roles') THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'custom_roles' AND column_name = 'org_id'
        ) THEN
            ALTER TABLE custom_roles RENAME COLUMN org_id TO tenant_id;
            RAISE NOTICE 'Migration 111 DOWN: custom_roles.org_id -> tenant_id';
        END IF;

        IF EXISTS (
            SELECT 1 FROM information_schema.table_constraints
            WHERE table_name = 'custom_roles' AND constraint_name = 'uq_custom_roles_org_name'
        ) THEN
            ALTER TABLE custom_roles RENAME CONSTRAINT uq_custom_roles_org_name TO uq_custom_roles_tenant_name;
            RAISE NOTICE 'Migration 111 DOWN: uq_custom_roles_org_name -> uq_custom_roles_tenant_name';
        END IF;

        IF EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE schemaname = 'public' AND tablename = 'custom_roles' AND indexname = 'idx_custom_roles_org_id'
        ) THEN
            ALTER INDEX idx_custom_roles_org_id RENAME TO idx_custom_roles_tenant_id;
            RAISE NOTICE 'Migration 111 DOWN: idx_custom_roles_org_id -> idx_custom_roles_tenant_id';
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'role_assignments') THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'role_assignments' AND column_name = 'org_id'
        ) THEN
            ALTER TABLE role_assignments RENAME COLUMN org_id TO tenant_id;
            RAISE NOTICE 'Migration 111 DOWN: role_assignments.org_id -> tenant_id';
        END IF;

        IF EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE schemaname = 'public' AND tablename = 'role_assignments' AND indexname = 'idx_role_assignments_org_id'
        ) THEN
            ALTER INDEX idx_role_assignments_org_id RENAME TO idx_role_assignments_tenant_id;
            RAISE NOTICE 'Migration 111 DOWN: idx_role_assignments_org_id -> idx_role_assignments_tenant_id';
        END IF;
    END IF;
END
$$;

-- ============================================================================
-- Recreate legacy RLS policies (USING-only shape per mig 023)
-- ============================================================================
-- Faithful to mig 023's original shape: USING only, no explicit WITH CHECK.
-- Postgres defaults WITH CHECK to the USING expression when omitted, so the
-- functional behavior is the same — but operators rolling back should be aware
-- that the canonical post-mig-111 shape (explicit WITH CHECK + canonical
-- policy name) is preferred. Roll-forward is preferred over roll-back; this
-- DOWN exists for emergency revert only.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'custom_roles') THEN
        CREATE POLICY custom_roles_tenant_isolation ON custom_roles
            USING (tenant_id = current_setting('app.current_org_id', true));
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'role_assignments') THEN
        CREATE POLICY role_assignments_tenant_isolation ON role_assignments
            USING (tenant_id = current_setting('app.current_org_id', true));
    END IF;
END
$$;

COMMIT;
