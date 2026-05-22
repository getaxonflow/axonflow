-- Migration 111: normalize custom_roles + role_assignments column to org_id
-- Date: 2026-05-22
--
-- ============================================================================
-- Why
-- ============================================================================
-- custom_roles + role_assignments were created with a `tenant_id` column —
-- predating the v9 identity normalization that aligned every other
-- multi-tenant table on `org_id`. Handler-side INSERT paths wrap in
-- withOrgScope, which sets `app.current_org_id` on the txn. Because the
-- prior RLS policy read `tenant_id = current_setting('app.current_org_id', true)`,
-- the comparison worked correctly — but the column-vs-GUC name mismatch was
-- transitional. This migration aligns the column with the canonical `org_id`,
-- recreates the RLS policy with the canonical `*_org_id_isolation` name shape
-- and an explicit WITH CHECK, and renames dependent constraints/indexes for
-- consistency with the rest of the v9 identity schema.
--
-- ============================================================================
-- Scope
-- ============================================================================
-- 1. ALTER TABLE custom_roles RENAME COLUMN tenant_id -> org_id
--    + RENAME CONSTRAINT uq_custom_roles_tenant_name -> uq_custom_roles_org_name
--    + RENAME INDEX idx_custom_roles_tenant_id -> idx_custom_roles_org_id
-- 2. ALTER TABLE role_assignments RENAME COLUMN tenant_id -> org_id
--    + RENAME INDEX idx_role_assignments_tenant_id -> idx_role_assignments_org_id
--    (the unique constraint uq_role_assignments_user_role does not carry
--    "tenant" in its name; left as-is.)
-- 3. DROP both old RLS policy names + CREATE with the canonical shape:
--    USING (org_id = current_setting('app.current_org_id', true))
--    WITH CHECK (org_id = current_setting('app.current_org_id', true))
-- 4. Smoke verify: no policy on these two tables still references the legacy
--    column name in its qual expression.
--
-- ============================================================================
-- Why ALTER RENAME COLUMN is data-safe
-- ============================================================================
-- Postgres ALTER TABLE RENAME COLUMN updates the column metadata in place
-- (no row rewrite). It takes a brief AccessExclusiveLock on the table for
-- the metadata flip, which blocks all readers AND writers on that table
-- until the BEGIN..COMMIT block below completes. Typical duration is sub-
-- 100ms on an idle table; but because this migration also DROPs + CREATEs
-- two RLS policies (each acquiring the same AccessExclusiveLock) and the
-- whole block holds the locks until COMMIT, plan the apply during a low-
-- write window (or take both tables briefly unavailable via the load
-- balancer if running under sustained write traffic).
--
-- All dependent objects — RLS policies, indexes, unique constraints, FKs,
-- triggers — track the column by attnum (not by name) so they continue to
-- reference the same column post-rename. The pg_policies.qual view
-- regenerates its text representation from the parsed expression, so post-
-- rename the qual reads "org_id = ..." even before we DROP+CREATE the policy.
--
-- We DROP+CREATE the policy anyway to (a) rename the policy from
-- *_tenant_isolation to *_org_id_isolation matching mig 110's convention,
-- and (b) add the explicit WITH CHECK clause that mig 023 omitted.
--
-- ============================================================================
-- Idempotency
-- ============================================================================
-- Every ALTER is guarded by an information_schema lookup so re-running the
-- migration on a DB where it already applied is a no-op. DROP POLICY IF EXISTS
-- handles both legacy and canonical policy names.

BEGIN;

-- ============================================================================
-- Step 1: custom_roles — rename column, constraint, index
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'custom_roles') THEN
        RAISE NOTICE 'Migration 111: custom_roles table not present; skipping';
        RETURN;
    END IF;

    -- Column rename — only if the legacy column still exists.
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'custom_roles' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE custom_roles RENAME COLUMN tenant_id TO org_id;
        RAISE NOTICE 'Migration 111: custom_roles.tenant_id -> org_id';
    ELSE
        RAISE NOTICE 'Migration 111: custom_roles.tenant_id already renamed; skipping column rename';
    END IF;

    -- Unique constraint rename for naming consistency with new column.
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'custom_roles' AND constraint_name = 'uq_custom_roles_tenant_name'
    ) THEN
        ALTER TABLE custom_roles RENAME CONSTRAINT uq_custom_roles_tenant_name TO uq_custom_roles_org_name;
        RAISE NOTICE 'Migration 111: uq_custom_roles_tenant_name -> uq_custom_roles_org_name';
    END IF;

    -- Index rename.
    IF EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = 'public' AND tablename = 'custom_roles' AND indexname = 'idx_custom_roles_tenant_id'
    ) THEN
        ALTER INDEX idx_custom_roles_tenant_id RENAME TO idx_custom_roles_org_id;
        RAISE NOTICE 'Migration 111: idx_custom_roles_tenant_id -> idx_custom_roles_org_id';
    END IF;
END
$$;

-- ============================================================================
-- Step 2: role_assignments — rename column, index
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'role_assignments') THEN
        RAISE NOTICE 'Migration 111: role_assignments table not present; skipping';
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'role_assignments' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE role_assignments RENAME COLUMN tenant_id TO org_id;
        RAISE NOTICE 'Migration 111: role_assignments.tenant_id -> org_id';
    ELSE
        RAISE NOTICE 'Migration 111: role_assignments.tenant_id already renamed; skipping column rename';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = 'public' AND tablename = 'role_assignments' AND indexname = 'idx_role_assignments_tenant_id'
    ) THEN
        ALTER INDEX idx_role_assignments_tenant_id RENAME TO idx_role_assignments_org_id;
        RAISE NOTICE 'Migration 111: idx_role_assignments_tenant_id -> idx_role_assignments_org_id';
    END IF;
END
$$;

-- ============================================================================
-- Step 3: Recreate RLS policies with canonical name + explicit WITH CHECK
-- ============================================================================
-- Only run if the table exists (community-only forks may not have either).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'custom_roles') THEN
        DROP POLICY IF EXISTS custom_roles_tenant_isolation ON custom_roles;
        DROP POLICY IF EXISTS custom_roles_org_id_isolation ON custom_roles;
        CREATE POLICY custom_roles_org_id_isolation ON custom_roles
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));
        RAISE NOTICE 'Migration 111: custom_roles RLS policy normalized';
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'role_assignments') THEN
        DROP POLICY IF EXISTS role_assignments_tenant_isolation ON role_assignments;
        DROP POLICY IF EXISTS role_assignments_org_id_isolation ON role_assignments;
        CREATE POLICY role_assignments_org_id_isolation ON role_assignments
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));
        RAISE NOTICE 'Migration 111: role_assignments RLS policy normalized';
    END IF;
END
$$;

-- ============================================================================
-- Step 4: Smoke verify — no policy on these tables references tenant_id
-- ============================================================================
DO $$
DECLARE
    legacy_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO legacy_count
    FROM pg_policies
    WHERE tablename IN ('custom_roles', 'role_assignments')
      AND qual LIKE '%tenant_id%';
    IF legacy_count > 0 THEN
        RAISE EXCEPTION 'Migration 111: % policies on custom_roles/role_assignments still reference tenant_id', legacy_count;
    END IF;

    -- Also verify the columns were renamed (catches a partial-apply scenario
    -- where Step 1/2 succeeded but Step 3's CREATE POLICY landed mid-flight).
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'custom_roles'
    ) AND EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'custom_roles' AND column_name = 'tenant_id'
    ) THEN
        RAISE EXCEPTION 'Migration 111: custom_roles.tenant_id still exists post-rename';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'role_assignments'
    ) AND EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'role_assignments' AND column_name = 'tenant_id'
    ) THEN
        RAISE EXCEPTION 'Migration 111: role_assignments.tenant_id still exists post-rename';
    END IF;
END
$$;

COMMIT;
