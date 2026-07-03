-- Migration 138: re-apply v9 org_id/RLS completion for tables created by
-- LATER-numbered enterprise migrations + allow 'redact' as an override action
-- Date: 2026-07-03 (#2808 / #2782)
--
-- ============================================================================
-- Why fresh enterprise deploys were broken (#2782)
-- ============================================================================
-- The migration runner sorts ALL directories by numeric version (core/ was
-- planned as 001-099, enterprise/ as 100-199 — but core now carries 100+
-- files). That means on a FRESH deploy:
--
--     core/106 (sso_* org_id + RLS completion)      runs at position 106
--     core/107 (connector_configs org_id + RLS)     runs at position 107
--     enterprise/108 CREATES sso_configurations/sso_sessions/sso_login_attempts
--     enterprise/120 CREATES connector_configs
--
-- 106/107 guard every step with IF EXISTS(table) — so on a fresh enterprise
-- deploy they silently no-op, and the tables come up:
--   * WITHOUT org_id  → the portal create handlers 500
--     ("pq: column \"org_id\" of relation \"connector_configs\" does not exist")
--   * WITHOUT the canonical app.current_org_id RLS policies and WITHOUT
--     FORCE ROW LEVEL SECURITY (connector_configs has ZERO policies)
--
-- Upgraded deploys (tables existed before 106/107 ran) were unaffected —
-- which is why this only surfaced on fresh partner-style installs.
--
-- This migration re-executes the SAME guarded, idempotent steps at position
-- 138 — after every migration that can create these tables (enterprise max
-- is 132 at the time of writing). On deploys where 106/107 already did the
-- work, every step is a no-op. On pure-community deploys NONE of these
-- tables exist — the sso_* tables are enterprise/108, and connector_configs
-- is customers-gated too (core/021 skips with "OSS mode" when `customers`,
-- an enterprise-only table, is absent) — so every guarded step skips and
-- the only community effect is the policy_overrides CHECK rebuild below
-- (policy_overrides IS core, mig 030).
--
-- ============================================================================
-- Also: policy_overrides action CHECK vs canonical override actions (#2808 E-9)
-- ============================================================================
-- The canonical override action list (platform/shared/policy/types.go
-- ValidOverrideActions) includes 'redact', the portal UI offers "Redact" in
-- the override modal, and static policies themselves use action='redact' —
-- but the DB CHECK rejects it, so creating a redact override failed with a
-- 500 CHECK violation. History: core/030a added redact, core/032 kept it,
-- and core/070 (policy_batch1_risk_and_override_extensions) SILENTLY DROPPED
-- redact when it last rewrote the constraint to {block,warn,log,allow,deny,
-- require_approval,log_only}. Rebuild the CHECK as the union of the canonical
-- list and the legacy values 070 permitted (allow/deny/log_only) so existing
-- rows stay valid.
--
-- ============================================================================
-- Idempotency
-- ============================================================================
-- Every step is IF EXISTS-guarded; ADD COLUMN IF NOT EXISTS, backfills touch
-- only org_id IS NULL rows, DROP POLICY IF EXISTS + CREATE POLICY, and
-- ENABLE/FORCE RLS are all idempotent. The CHECK is dropped and re-added in
-- one transaction. All target tables are small config tables (SSO configs,
-- connector configs, overrides), so the full-table validations complete
-- near-instantly.

BEGIN;

-- ============================================================================
-- Step 1: sso_* tables — org_id column (mirror of core/106 Step 1)
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sso_configurations') THEN
        ALTER TABLE sso_configurations ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);
        ALTER TABLE sso_sessions       ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);
        ALTER TABLE sso_login_attempts ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);
        RAISE NOTICE 'Migration 138: ensured org_id columns on sso_* tables';
    ELSE
        RAISE NOTICE 'Migration 138: sso_configurations not present (community-only deploy); skipping sso steps';
    END IF;
END
$$;

-- ============================================================================
-- Step 2: sso_* backfill from tenant_id (mirror of core/106 Step 2)
-- ============================================================================
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
    END IF;
END
$$;

-- ============================================================================
-- Step 3: sso_* org_id NOT NULL (mirror of core/106 Step 3)
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sso_configurations') THEN
        ALTER TABLE sso_configurations ALTER COLUMN org_id SET NOT NULL;
        ALTER TABLE sso_sessions       ALTER COLUMN org_id SET NOT NULL;
        ALTER TABLE sso_login_attempts ALTER COLUMN org_id SET NOT NULL;
    END IF;
END
$$;

-- ============================================================================
-- Step 4: sso_* canonical app.current_org_id policies (mirror of core/106 Step 4)
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sso_configurations') THEN
        DROP POLICY IF EXISTS sso_configurations_tenant_isolation ON sso_configurations;
        DROP POLICY IF EXISTS sso_sessions_tenant_isolation       ON sso_sessions;
        DROP POLICY IF EXISTS sso_login_attempts_tenant_isolation ON sso_login_attempts;

        DROP POLICY IF EXISTS sso_configurations_org_id_isolation ON sso_configurations;
        DROP POLICY IF EXISTS sso_sessions_org_id_isolation       ON sso_sessions;
        DROP POLICY IF EXISTS sso_login_attempts_org_id_isolation ON sso_login_attempts;

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
    END IF;
END
$$;

-- ============================================================================
-- Step 5: sso_* ENABLE + FORCE RLS (mirror of core/106 Step 5)
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
    END IF;
END
$$;

-- ============================================================================
-- Step 6: portal_check_sso_availability queries by org_id (mirror of core/106 Step 6)
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_proc
        WHERE proname = 'portal_check_sso_availability'
          AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        RAISE NOTICE 'Migration 138 Step 6 skipped: portal_check_sso_availability not installed';
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

        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
            REVOKE EXECUTE ON FUNCTION portal_check_sso_availability(VARCHAR) FROM PUBLIC;
            GRANT EXECUTE ON FUNCTION portal_check_sso_availability(VARCHAR) TO axonflow_app_role;
        END IF;
    END IF;
END
$$;

-- ============================================================================
-- Step 7: connector_configs — org_id + backfill + NOT NULL (mirror of core/107 Steps 1-3)
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connector_configs') THEN
        ALTER TABLE connector_configs ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);

        -- Backfill from `tenants` (core/062 — present on EVERY topology),
        -- mirroring core/107 Step 2 exactly. NOTE: on a pure-community deploy
        -- connector_configs does NOT exist (core/021 is customers-gated and
        -- `customers` is enterprise-only), so this whole step skips via the
        -- IF EXISTS guard above — the community boot path never reaches this
        -- UPDATE. `tenants` is still the correct source over `customers`:
        -- it is the canonical org-of-tenant lookup post mig-100 and exists
        -- on every topology where this step CAN run.
        UPDATE connector_configs cc
        SET org_id = COALESCE(
            (SELECT t.org_id FROM tenants t WHERE t.tenant_id = cc.tenant_id LIMIT 1),
            cc.tenant_id
        )
        WHERE cc.org_id IS NULL;

        ALTER TABLE connector_configs ALTER COLUMN org_id SET NOT NULL;
        RAISE NOTICE 'Migration 138: ensured org_id on connector_configs';
    ELSE
        RAISE NOTICE 'Migration 138: connector_configs not present; skipping';
    END IF;
END
$$;

-- ============================================================================
-- Step 8: connector_configs — canonical policy + ENABLE + FORCE (mirror of core/107 Steps 4-5)
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connector_configs') THEN
        ALTER TABLE connector_configs ENABLE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS connector_configs_org_id_isolation ON connector_configs;
        CREATE POLICY connector_configs_org_id_isolation ON connector_configs
            FOR ALL
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));
        ALTER TABLE connector_configs FORCE ROW LEVEL SECURITY;
    END IF;
END
$$;

-- ============================================================================
-- Step 9: policy_overrides action CHECK — add 'redact' (E-9)
-- ============================================================================
-- Union of the canonical ValidOverrideActions (block, require_approval,
-- redact, warn, log) and the legacy values the previous CHECK permitted
-- (allow, deny, log_only) so existing rows remain valid.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'policy_overrides') THEN
        ALTER TABLE policy_overrides DROP CONSTRAINT IF EXISTS policy_overrides_action_override_check;
        ALTER TABLE policy_overrides
            ADD CONSTRAINT policy_overrides_action_override_check
            CHECK (action_override IN (
                'block', 'require_approval', 'redact', 'warn', 'log',
                'allow', 'deny', 'log_only'
            ));
        RAISE NOTICE 'Migration 138: policy_overrides action CHECK now permits redact';
    END IF;
END
$$;

-- ============================================================================
-- Smoke verification — loud failure if the completion did not take
-- ============================================================================
DO $$
DECLARE
    r RECORD;
    tbl TEXT;
    sso_tables TEXT[] := ARRAY['sso_configurations', 'sso_sessions', 'sso_login_attempts'];
BEGIN
    -- sso_* (only when present)
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sso_configurations') THEN
        FOREACH tbl IN ARRAY sso_tables LOOP
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = tbl AND column_name = 'org_id'
            ) THEN
                RAISE EXCEPTION 'Migration 138 failed: % missing org_id', tbl;
            END IF;
            FOR r IN
                SELECT relname, relforcerowsecurity FROM pg_class
                WHERE relname = tbl AND relkind = 'r'
            LOOP
                IF NOT r.relforcerowsecurity THEN
                    RAISE EXCEPTION 'Migration 138 failed: FORCE RLS not active on %', r.relname;
                END IF;
            END LOOP;
            IF NOT EXISTS (
                SELECT 1 FROM pg_policies p
                WHERE p.tablename = tbl AND p.qual LIKE '%app.current_org_id%'
            ) THEN
                RAISE EXCEPTION 'Migration 138 failed: % has no app.current_org_id policy', tbl;
            END IF;
        END LOOP;
    END IF;

    -- connector_configs (only when present)
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connector_configs') THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'connector_configs' AND column_name = 'org_id'
        ) THEN
            RAISE EXCEPTION 'Migration 138 failed: connector_configs missing org_id';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM pg_class
            WHERE relname = 'connector_configs' AND relforcerowsecurity
        ) THEN
            RAISE EXCEPTION 'Migration 138 failed: FORCE RLS not active on connector_configs';
        END IF;
    END IF;

    -- redact must satisfy the rebuilt CHECK
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'policy_overrides') THEN
        IF EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'policy_overrides_action_override_check'
              AND pg_get_constraintdef(oid) NOT LIKE '%redact%'
        ) THEN
            RAISE EXCEPTION 'Migration 138 failed: policy_overrides CHECK still rejects redact';
        END IF;
    END IF;

    RAISE NOTICE 'Migration 138 verified';
END
$$;

COMMIT;
