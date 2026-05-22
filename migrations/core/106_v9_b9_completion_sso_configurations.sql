-- Migration 106: sso_configurations org_id column + canonical RLS policy
-- + FORCE ROW LEVEL SECURITY
-- Date: 2026-05-21
--
-- ============================================================================
-- Why this defers from migration 103
-- ============================================================================
-- sso_configurations was deliberately excluded from migration 103 because of
-- column-name + GUC mismatch:
--   - Existing schema (enterprise mig 108) keys on tenant_id, NOT org_id
--   - Existing policy uses app.tenant_id GUC, NOT the canonical
--     app.current_org_id used by every other B-batch table
--
-- Shipping FORCE on the table under the current policy would: (a) require
-- all callers to also `set_config('app.tenant_id', ...)` separately from
-- app.current_org_id, which no existing handler does; (b) make the
-- type-confusion permanent in the wire protocol.
--
-- The fix is a paired column rename + policy migration:
--   1. Add `org_id` column (nullable, then backfill, then NOT NULL)
--   2. Backfill from tenant_id (it stored the org_id value per the
--      auth.go:78-82 comment block — the column was misnamed historically)
--   3. Drop the app.tenant_id policy
--   4. Create new policy on app.current_org_id + org_id column
--   5. FORCE
--   6. Update portal_check_sso_availability (mig 104) to query by org_id
--
-- Same shape applied to the sister tables sso_sessions + sso_login_attempts
-- (both keyed on tenant_id in mig 108).
--
-- ============================================================================
-- Why we don't drop the tenant_id column
-- ============================================================================
-- The Go code (sso handlers, marketplace) still references `tenant_id` in
-- writes. Renaming the column would require a coordinated code+migration
-- deploy. Instead we add org_id alongside, backfill, FORCE on org_id, and
-- leave tenant_id as a deprecated alias. A future major version can drop
-- the column once all writers are migrated to org_id.
--
-- ============================================================================
-- Idempotency
-- ============================================================================
-- ADD COLUMN IF NOT EXISTS is idempotent.
-- The backfill UPDATE only touches rows where org_id IS NULL.
-- DROP POLICY IF EXISTS + CREATE POLICY is idempotent.
-- CREATE OR REPLACE FUNCTION (for portal_check_sso_availability update)
-- is idempotent.

BEGIN;

-- ============================================================================
-- Step 1: ADD org_id column on sso_configurations + sister tables
-- ============================================================================
-- Nullable on add to allow the backfill UPDATE. We tighten to NOT NULL
-- after the backfill below.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sso_configurations') THEN
        ALTER TABLE sso_configurations ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);
        ALTER TABLE sso_sessions       ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);
        ALTER TABLE sso_login_attempts ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);
        RAISE NOTICE 'Migration 106: added org_id columns to sso_* tables';
    ELSE
        RAISE NOTICE 'Migration 106: sso_configurations table not present (community-only deploy); skipping';
    END IF;
END
$$;

-- ============================================================================
-- Step 2: Backfill org_id from tenant_id
-- ============================================================================
-- Per auth.go:78-82 comment: "The sso_configurations table uses tenant_id
-- as its key historically, but it stores the org_id value." So the
-- backfill is a direct copy.
--
-- For rows where tenants.org_id JOIN resolves differently (post mig-100
-- cs_* customers where tenant_id != org_id), prefer the joined value.
-- Falls back to tenant_id when no tenants row exists.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sso_configurations') THEN
        UPDATE sso_configurations s
        SET org_id = COALESCE(
            (SELECT t.org_id FROM tenants t WHERE t.tenant_id = s.tenant_id LIMIT 1),
            s.tenant_id
        )
        WHERE s.org_id IS NULL;

        UPDATE sso_sessions s
        SET org_id = COALESCE(
            (SELECT t.org_id FROM tenants t WHERE t.tenant_id = s.tenant_id LIMIT 1),
            s.tenant_id
        )
        WHERE s.org_id IS NULL;

        UPDATE sso_login_attempts s
        SET org_id = COALESCE(
            (SELECT t.org_id FROM tenants t WHERE t.tenant_id = s.tenant_id LIMIT 1),
            s.tenant_id
        )
        WHERE s.org_id IS NULL;

        RAISE NOTICE 'Migration 106: backfilled org_id on sso_* rows';
    END IF;
END
$$;

-- ============================================================================
-- Step 3: Tighten org_id to NOT NULL
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sso_configurations') THEN
        ALTER TABLE sso_configurations ALTER COLUMN org_id SET NOT NULL;
        ALTER TABLE sso_sessions       ALTER COLUMN org_id SET NOT NULL;
        ALTER TABLE sso_login_attempts ALTER COLUMN org_id SET NOT NULL;
        RAISE NOTICE 'Migration 106: org_id SET NOT NULL on sso_* tables';
    END IF;
END
$$;

-- ============================================================================
-- Step 4: Drop old app.tenant_id policies + create new app.current_org_id policies
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sso_configurations') THEN
        DROP POLICY IF EXISTS sso_configurations_tenant_isolation ON sso_configurations;
        DROP POLICY IF EXISTS sso_sessions_tenant_isolation       ON sso_sessions;
        DROP POLICY IF EXISTS sso_login_attempts_tenant_isolation ON sso_login_attempts;

        CREATE POLICY sso_configurations_org_id_isolation ON sso_configurations
            FOR ALL
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));

        CREATE POLICY sso_sessions_org_id_isolation ON sso_sessions
            FOR ALL
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));

        CREATE POLICY sso_login_attempts_org_id_isolation ON sso_login_attempts
            FOR ALL
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));

        RAISE NOTICE 'Migration 106: replaced app.tenant_id policies with app.current_org_id policies on sso_* tables';
    END IF;
END
$$;

-- ============================================================================
-- Step 5: FORCE RLS on sso_configurations + sister tables
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sso_configurations') THEN
        ALTER TABLE sso_configurations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE sso_sessions       ENABLE ROW LEVEL SECURITY;
        ALTER TABLE sso_login_attempts ENABLE ROW LEVEL SECURITY;

        ALTER TABLE sso_configurations FORCE ROW LEVEL SECURITY;
        ALTER TABLE sso_sessions       FORCE ROW LEVEL SECURITY;
        ALTER TABLE sso_login_attempts FORCE ROW LEVEL SECURITY;

        RAISE NOTICE 'Migration 106: FORCE RLS active on sso_* tables';
    END IF;
END
$$;

-- ============================================================================
-- Step 6: Update portal_check_sso_availability (mig 104) to query by org_id
-- ============================================================================
-- mig 104 defined this function with `WHERE s.tenant_id = p_org_id` (with
-- the comment that the historic column-naming carries org_id semantics).
-- Post-this-migration, sso_configurations has a real org_id column with
-- per-row backfilled values. Update the function body to use it.
--
-- This step ONLY runs if mig 104 created the function. Without this gate,
-- CREATE OR REPLACE would silently CREATE the function on a deploy that ran
-- mig 106 before mig 104 — the resulting function would have mig-106 body
-- semantics that callers expecting mig 104's signature might not anticipate.
-- The gate ensures mig 106 only UPDATES an existing function, never CREATES
-- one. When mig 104 lands later, its own CREATE OR REPLACE installs the
-- function, then a re-run of mig 106 (idempotent) updates the body to the
-- post-org_id version.
--
-- Skipped entirely when sso_configurations is absent (community-only deploy).
DO $$
BEGIN
    -- Belt-and-suspenders gate: only proceed if mig 104 has installed
    -- portal_check_sso_availability AND sso_configurations exists.
    IF NOT EXISTS (
        SELECT 1 FROM pg_proc
        WHERE proname = 'portal_check_sso_availability'
          AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        RAISE NOTICE 'Migration 106 Step 6 skipped: portal_check_sso_availability not installed (mig 104 not yet applied)';
        RETURN;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sso_configurations') THEN
        CREATE OR REPLACE FUNCTION portal_check_sso_availability(p_org_id VARCHAR)
            RETURNS TABLE(
                org_exists  BOOLEAN,
                provider    VARCHAR,
                enabled     BOOLEAN,
                enforce_sso BOOLEAN
            )
            LANGUAGE plpgsql
            STABLE
            SECURITY DEFINER
            SET search_path = public, pg_temp
        AS $body$
        DECLARE
            v_exists BOOLEAN;
        BEGIN
            SELECT EXISTS(
                SELECT 1 FROM organizations
                WHERE org_id = p_org_id AND status = 'ACTIVE'
            ) INTO v_exists;

            IF NOT v_exists THEN
                RETURN QUERY SELECT FALSE, NULL::VARCHAR, FALSE, FALSE;
                RETURN;
            END IF;

            RETURN QUERY
            SELECT TRUE, s.provider, s.enabled, s.enforce_sso
            FROM sso_configurations s
            WHERE s.org_id = p_org_id
            LIMIT 1;

            IF NOT FOUND THEN
                RETURN QUERY SELECT TRUE, NULL::VARCHAR, FALSE, FALSE;
            END IF;
        END;
        $body$;

        -- Re-grant after CREATE OR REPLACE (grants survive REPLACE but
        -- belt-and-suspenders for fresh installs).
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
            REVOKE EXECUTE ON FUNCTION portal_check_sso_availability(VARCHAR) FROM PUBLIC;
            GRANT EXECUTE ON FUNCTION portal_check_sso_availability(VARCHAR) TO axonflow_app_role;
        END IF;

        RAISE NOTICE 'Migration 106: portal_check_sso_availability updated to query by org_id';
    END IF;
END
$$;

-- ============================================================================
-- Smoke verification — NOT EXISTS pattern per mig 103
-- ============================================================================
DO $$
DECLARE
    r RECORD;
    expected_tables TEXT[] := ARRAY['sso_configurations', 'sso_sessions', 'sso_login_attempts'];
    tbl TEXT;
BEGIN
    -- Skip entire smoke when sso_* tables absent (community-only deploy).
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sso_configurations') THEN
        RAISE NOTICE 'Migration 106 smoke skipped: sso_* tables not present';
        RETURN;
    END IF;

    FOREACH tbl IN ARRAY expected_tables LOOP
        FOR r IN
            SELECT relname,
                   relrowsecurity AS rls_enabled,
                   relforcerowsecurity AS rls_forced
            FROM pg_class
            WHERE relname = tbl AND relkind = 'r'
        LOOP
            IF NOT r.rls_enabled THEN
                RAISE EXCEPTION 'Migration 106 failed: RLS not enabled on %', r.relname;
            END IF;
            IF NOT r.rls_forced THEN
                RAISE EXCEPTION 'Migration 106 failed: FORCE RLS not active on %', r.relname;
            END IF;
        END LOOP;
    END LOOP;

    FOR r IN
        SELECT t.tbl AS table_name
        FROM unnest(expected_tables) AS t(tbl)
        WHERE NOT EXISTS (
            SELECT 1 FROM pg_policies p
            WHERE p.tablename = t.tbl
              AND p.qual LIKE '%app.current_org_id%'
        )
    LOOP
        RAISE EXCEPTION 'Migration 106 failed: % has no app.current_org_id isolation policy', r.table_name;
    END LOOP;

    -- Assert no remaining app.tenant_id policy on these tables (mig 108's
    -- legacy policies should have been dropped in Step 4).
    IF EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = ANY(expected_tables)
          AND qual LIKE '%app.tenant_id%'
    ) THEN
        RAISE EXCEPTION 'Migration 106 failed: app.tenant_id policy still present on a sso_* table';
    END IF;

    RAISE NOTICE 'Migration 106 verified: sso_* tables FORCEd with app.current_org_id policy';
END
$$;

COMMIT;
