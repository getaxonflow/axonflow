-- Migration 107: FORCE RLS on misc customer-scope tables
-- Date: 2026-05-21
--
-- ============================================================================
-- Scope — what this migration FORCES
-- ============================================================================
-- Four customer-scope tables:
--   1. connectors             — has org_id (mig 012, nullable); backfill + NOT NULL + FORCE
--   2. connector_configs      — NO org_id today; ADD COLUMN + backfill + NOT NULL + FORCE
--   3. agent_heartbeats       — has org_id (mig 101, nullable); backfill + NOT NULL + FORCE
--   4. node_violations        — has org_id NOT NULL (mig 105); just FORCE + policy
--
-- Out of scope:
--   - service_identities + license_keys — deployment-scope (zero Go runtime
--     callers as of 2026-05-21); deployment_admin paths only. No FORCE
--     migration for these tables.
--
-- ============================================================================
-- Idempotency
-- ============================================================================
-- ADD COLUMN IF NOT EXISTS + UPDATE WHERE NULL + ALTER COLUMN SET NOT NULL is
-- idempotent on re-run (column exists, NULLs already populated, NOT NULL
-- constraint already in place).
-- ALTER TABLE ENABLE/FORCE RLS is idempotent.
-- DROP POLICY IF EXISTS + CREATE POLICY is idempotent.

BEGIN;

-- ============================================================================
-- Step 1: connector_configs — ADD COLUMN org_id (only table missing it)
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connector_configs') THEN
        ALTER TABLE connector_configs ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);
        RAISE NOTICE 'Migration 107: added org_id to connector_configs';
    ELSE
        RAISE NOTICE 'Migration 107: connector_configs table not present (community-only deploy); skipping';
    END IF;
END
$$;

-- ============================================================================
-- Step 2: Backfill org_id on connectors + connector_configs + agent_heartbeats
-- ============================================================================
-- All three backfill from `tenants.org_id` (the canonical org-of-tenant
-- lookup post mig-100). Fall back to existing tenant_id value if no
-- tenants row exists — preserves the legacy collapse where tenant_id ==
-- org_id (pre-mig-100 customers + community-mode deploys).
DO $$
BEGIN
    -- connectors: tenant_id → org_id via tenants table
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connectors') THEN
        UPDATE connectors c
        SET org_id = COALESCE(
            (SELECT t.org_id FROM tenants t WHERE t.tenant_id = c.tenant_id LIMIT 1),
            c.tenant_id
        )
        WHERE c.org_id IS NULL;
    END IF;

    -- connector_configs: same path
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connector_configs') THEN
        UPDATE connector_configs cc
        SET org_id = COALESCE(
            (SELECT t.org_id FROM tenants t WHERE t.tenant_id = cc.tenant_id LIMIT 1),
            cc.tenant_id
        )
        WHERE cc.org_id IS NULL;
    END IF;

    -- agent_heartbeats: backfill from license_key_hash → organizations join.
    -- Heartbeats don't carry tenant_id directly. The license_key_hash points
    -- to an organizations row (via the license-key-hash convention) but
    -- there's no foreign-key. Best-effort backfill: rows that already have
    -- a known org_id stay; the NULL rows that we can't resolve get the
    -- sentinel 'unresolved-heartbeat-pre-mig107' so the NOT NULL constraint
    -- can apply. Operators can re-resolve via the legacy migration paths
    -- post-deploy.
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_heartbeats') THEN
        UPDATE agent_heartbeats
        SET org_id = 'unresolved-heartbeat-pre-mig107'
        WHERE org_id IS NULL;
    END IF;

    RAISE NOTICE 'Migration 107: backfilled org_id on connectors/connector_configs/agent_heartbeats';
END
$$;

-- ============================================================================
-- Step 3: Tighten org_id to NOT NULL
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connectors') THEN
        ALTER TABLE connectors ALTER COLUMN org_id SET NOT NULL;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connector_configs') THEN
        ALTER TABLE connector_configs ALTER COLUMN org_id SET NOT NULL;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_heartbeats') THEN
        ALTER TABLE agent_heartbeats ALTER COLUMN org_id SET NOT NULL;
    END IF;
    -- node_violations.org_id is already NOT NULL (mig 105).
    RAISE NOTICE 'Migration 107: org_id SET NOT NULL on connectors/connector_configs/agent_heartbeats';
END
$$;

-- ============================================================================
-- Step 4: ENABLE + canonical app.current_org_id policies on all 4 tables
-- ============================================================================
DO $$
BEGIN
    -- connectors
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connectors') THEN
        ALTER TABLE connectors ENABLE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS connectors_org_id_isolation ON connectors;
        CREATE POLICY connectors_org_id_isolation ON connectors
            FOR ALL
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));
    END IF;

    -- connector_configs
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connector_configs') THEN
        ALTER TABLE connector_configs ENABLE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS connector_configs_org_id_isolation ON connector_configs;
        CREATE POLICY connector_configs_org_id_isolation ON connector_configs
            FOR ALL
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));
    END IF;

    -- agent_heartbeats
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_heartbeats') THEN
        ALTER TABLE agent_heartbeats ENABLE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS agent_heartbeats_org_id_isolation ON agent_heartbeats;
        CREATE POLICY agent_heartbeats_org_id_isolation ON agent_heartbeats
            FOR ALL
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));
    END IF;

    -- node_violations
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'node_violations') THEN
        ALTER TABLE node_violations ENABLE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS node_violations_org_id_isolation ON node_violations;
        CREATE POLICY node_violations_org_id_isolation ON node_violations
            FOR ALL
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));
    END IF;
    RAISE NOTICE 'Migration 107: ENABLE+policy on connectors/connector_configs/agent_heartbeats/node_violations';
END
$$;

-- ============================================================================
-- Step 5: FORCE — what this migration is about
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connectors') THEN
        ALTER TABLE connectors FORCE ROW LEVEL SECURITY;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connector_configs') THEN
        ALTER TABLE connector_configs FORCE ROW LEVEL SECURITY;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_heartbeats') THEN
        ALTER TABLE agent_heartbeats FORCE ROW LEVEL SECURITY;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'node_violations') THEN
        ALTER TABLE node_violations FORCE ROW LEVEL SECURITY;
    END IF;
    RAISE NOTICE 'Migration 107: FORCE RLS active on all 4 misc customer-scope tables';
END
$$;

-- ============================================================================
-- Smoke verification — NOT EXISTS pattern per mig 103
-- ============================================================================
DO $$
DECLARE
    r RECORD;
    expected_tables TEXT[] := ARRAY['connectors', 'connector_configs', 'agent_heartbeats', 'node_violations'];
    tbl TEXT;
    present_tables TEXT[] := ARRAY[]::TEXT[];
BEGIN
    -- Build the list of tables actually present (handles community-only
    -- deploys that may lack some enterprise tables).
    FOREACH tbl IN ARRAY expected_tables LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = tbl) THEN
            present_tables := array_append(present_tables, tbl);
        END IF;
    END LOOP;

    -- Assert FORCE RLS active on every present table.
    FOREACH tbl IN ARRAY present_tables LOOP
        FOR r IN
            SELECT relname,
                   relrowsecurity AS rls_enabled,
                   relforcerowsecurity AS rls_forced
            FROM pg_class
            WHERE relname = tbl AND relkind = 'r'
        LOOP
            IF NOT r.rls_enabled THEN
                RAISE EXCEPTION 'Migration 107 failed: RLS not enabled on %', r.relname;
            END IF;
            IF NOT r.rls_forced THEN
                RAISE EXCEPTION 'Migration 107 failed: FORCE RLS not active on %', r.relname;
            END IF;
        END LOOP;
    END LOOP;

    -- Assert each present table has a canonical app.current_org_id policy.
    FOR r IN
        SELECT t.tbl AS table_name
        FROM unnest(present_tables) AS t(tbl)
        WHERE NOT EXISTS (
            SELECT 1 FROM pg_policies p
            WHERE p.tablename = t.tbl
              AND p.qual LIKE '%app.current_org_id%'
        )
    LOOP
        RAISE EXCEPTION 'Migration 107 failed: % has no app.current_org_id isolation policy', r.table_name;
    END LOOP;

    RAISE NOTICE 'Migration 107 verified: % misc customer-scope tables FORCEd', array_length(present_tables, 1);
END
$$;

COMMIT;
