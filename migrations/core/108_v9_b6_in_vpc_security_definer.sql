-- Migration 108: in-VPC enterprise SECURITY DEFINER + FORCE RLS
-- Date: 2026-05-21
--
-- Mirrors the SaaS-side fix from migration 104 for the in-VPC enterprise
-- auth path.
--
-- ============================================================================
-- What this migration does
-- ============================================================================
-- The in-VPC enterprise auth path runs
-- `platform/agent/db_auth.go::validateClientCredentialsDB` ->
-- `validateViaAPIKeys` (db_auth.go:101). That function issues
--
--   SELECT ... FROM api_keys k
--   JOIN   customers c ON k.customer_id = c.customer_id
--   JOIN   pricing_tiers pt ON c.tier = pt.tier
--                          AND c.deployment_mode = pt.deployment_mode
--   WHERE  k.license_key_hash = $1
--     AND  k.enabled = true
--     AND  c.enabled = true
--     AND  c.status  = 'active'
--
-- BEFORE `app.current_org_id` can be established. Same chicken-and-egg shape as
-- the SaaS path (`validateCommunityRegistration` -> `auth_lookup_org`) which
-- migration 104 closed via the `portal_auth_lookup_org` SECURITY DEFINER
-- helper. The in-VPC path needs the equivalent.
--
-- Without this fix, the per-stack `AXONFLOW_DB_USE_APP_ROLE=true` flip CANNOT
-- ship on any in-VPC enterprise customer deploy because under
-- `axonflow_app_role` (NOBYPASSRLS, migration 098) the JOIN above returns
-- zero rows once FORCE RLS lands on `api_keys` + `customers`.
--
-- This migration:
--
--   1. Creates `auth_lookup_api_key(p_license_key_hash TEXT) RETURNS TABLE`
--      SECURITY DEFINER function that runs as the function's owner (RDS
--      master / BYPASSRLS) and returns ONLY the auth-needed columns —
--      mirroring the validateViaAPIKeys SELECT shape one-for-one.
--   2. Creates `auth_touch_api_key(p_api_key_id VARCHAR) RETURNS VOID`
--      SECURITY DEFINER function for the post-auth fire-and-forget
--      `updateAPIKeyLastUsed` goroutine which UPDATES api_keys without a GUC.
--   3. Backfills `api_keys.org_id` + `customers.org_id` so every existing
--      row carries a non-empty `org_id` value before FORCE RLS lands.
--   4. ENABLE + FORCE ROW LEVEL SECURITY on `api_keys` + `customers`, with
--      an `org_id = current_setting('app.current_org_id', true)` policy on
--      each (USING + WITH CHECK). Both tables already carry an `org_id`
--      column via migration 002 (api_keys ALTER ADD COLUMN) + migration
--      enterprise/100 (customers CREATE TABLE).
--
-- `pricing_tiers` is INTENTIONALLY LEFT UNFORCED — it is deployment-scope
-- (every customer sees the same tier definitions), keyed on
-- `(tier, deployment_mode)` with NO `org_id` column, so a per-org RLS policy
-- is semantically wrong. Cross-org reads via the SECURITY DEFINER helper are
-- the correct path; the function owner BYPASSes any RLS that ever lands on
-- pricing_tiers in the future.
--
-- ============================================================================
-- Deployment-mode safety
-- ============================================================================
-- `customers` lives in `migrations/enterprise/100_billing_and_metering.sql`.
-- The validateViaAPIKeys api_keys schema (api_key_id, customer_id,
-- license_key_hash, ...) lives in the operator-managed
-- `platform/database/migrations/006_option3_auth_system.sql`. Community-mode
-- deployments (DEPLOYMENT_MODE=community / evaluation) run core/ migrations
-- ONLY — they have the migration-002 api_keys schema (id, org_id, key_hash,
-- key_prefix, ...) and NO customers/pricing_tiers tables.
--
-- This migration is community-safe via DO-block `IF EXISTS` guards: when
-- `customers` doesn't exist OR `api_keys.license_key_hash` column doesn't
-- exist, the FORCE-RLS branch is skipped with a RAISE NOTICE. The SECURITY
-- DEFINER functions are still installed (idempotent CREATE OR REPLACE);
-- they're only invoked from `validateViaAPIKeys`, which itself short-
-- circuits when the schema doesn't match.
--
-- ============================================================================
-- Idempotency
-- ============================================================================
-- CREATE OR REPLACE FUNCTION is idempotent. REVOKE/GRANT is idempotent.
-- ALTER TABLE ... ENABLE/FORCE ROW LEVEL SECURITY is idempotent.
-- DROP POLICY IF EXISTS + CREATE POLICY is idempotent. Backfills are
-- guarded with WHERE `org_id IS NULL OR org_id = ''` (no-op on re-run).
--
-- ============================================================================
-- Depends on:
-- ============================================================================
--   098 — axonflow_app_role + axonflow_platform_admin roles
--   002 — api_keys.org_id column (added via ALTER TABLE in mig 002)
--   enterprise/100 — customers table (column-checked via IF EXISTS; not a
--                    hard dependency since community mode runs without it)

BEGIN;

-- ============================================================================
-- auth_lookup_api_key — SECURITY DEFINER pre-auth lookup
-- ============================================================================
-- RETURN TABLE column list mirrors validateViaAPIKeys SELECT order
-- (platform/agent/db_auth.go:107-138) one-for-one. Any future drift between
-- this declaration and the Go-side Scan() order will surface as a
-- column-mismatch error at runtime — caught by the R2 integration test in
-- this PR.
--
-- The customers.customer_id + customers.enabled columns share names with
-- api_keys.customer_id + api_keys.enabled. The RETURN TABLE aliases the
-- customers-side fields with a `c_` prefix to avoid the ambiguous-column
-- error at function-create time. The Go Scan() reads positionally so the
-- alias names don't affect the call site.
--
-- Function is STABLE (no side effects, same input -> same output within a
-- statement) so the query planner can elide repeated calls.
CREATE OR REPLACE FUNCTION auth_lookup_api_key(p_license_key_hash TEXT)
    RETURNS TABLE(
        -- api_keys columns (13)
        api_key_id          VARCHAR,
        customer_id         VARCHAR,
        license_key         VARCHAR,
        key_name            VARCHAR,
        key_type            VARCHAR,
        expires_at          TIMESTAMPTZ,
        grace_period_days   INTEGER,
        permissions         JSONB,
        custom_rate_limit   INTEGER,
        enabled             BOOLEAN,
        revoked_at          TIMESTAMPTZ,
        last_used_at        TIMESTAMPTZ,
        total_requests      BIGINT,
        -- customers columns (8) — c_ prefix avoids name collision with
        -- api_keys.customer_id + api_keys.enabled in the RETURN TABLE.
        c_customer_id       VARCHAR,
        organization_name   VARCHAR,
        organization_id     VARCHAR,
        deployment_mode     VARCHAR,
        tier                VARCHAR,
        tenant_id           VARCHAR,
        status              VARCHAR,
        c_enabled           BOOLEAN,
        -- pricing_tiers columns (1)
        requests_per_minute INTEGER
    )
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
BEGIN
    -- The function body is parsed at CREATE time but column references are
    -- resolved at INVOCATION. On community-mode databases where the
    -- 006_option3_auth_system api_keys schema isn't applied, calls to this
    -- function will error with "column does not exist" — validateViaAPIKeys
    -- catches that error and falls through to validateViaOrganizations,
    -- preserving the existing fallback semantics.
    RETURN QUERY
    SELECT
        k.api_key_id::VARCHAR,
        k.customer_id::VARCHAR,
        k.license_key::VARCHAR,
        k.key_name::VARCHAR,
        k.key_type::VARCHAR,
        k.expires_at,
        k.grace_period_days,
        k.permissions,
        k.custom_rate_limit,
        k.enabled,
        k.revoked_at,
        k.last_used_at,
        k.total_requests,
        c.customer_id::VARCHAR,
        c.organization_name,
        c.organization_id,
        c.deployment_mode,
        c.tier,
        c.tenant_id,
        c.status,
        c.enabled,
        pt.requests_per_minute
    FROM api_keys k
    JOIN customers c ON k.customer_id = c.customer_id
    JOIN pricing_tiers pt ON c.tier = pt.tier
                         AND c.deployment_mode = pt.deployment_mode
    WHERE k.license_key_hash = p_license_key_hash
      AND k.enabled = true
      AND c.enabled = true
      AND c.status  = 'active';
END;
$$;

COMMENT ON FUNCTION auth_lookup_api_key(TEXT) IS
    'SECURITY DEFINER pre-auth lookup for in-VPC enterprise auth. Mirrors '
    'the SaaS portal_auth_lookup_org pattern (mig 104). Bypasses FORCE RLS on '
    'api_keys + customers + pricing_tiers because the GUC app.current_org_id '
    'cannot be set before the lookup completes.';

-- ============================================================================
-- auth_touch_api_key — SECURITY DEFINER post-auth last_used_at update
-- ============================================================================
-- `updateAPIKeyLastUsed` is called as a fire-and-forget goroutine after a
-- successful validateViaAPIKeys lookup. It runs on a fresh DB conn that
-- does NOT carry the auth handler's transactional GUC, so under FORCE RLS
-- on api_keys the UPDATE would match 0 rows. SECURITY DEFINER restores the
-- behavior (same pattern as register_org/register_tenant in mig 104).
CREATE OR REPLACE FUNCTION auth_touch_api_key(p_api_key_id VARCHAR)
    RETURNS VOID
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
BEGIN
    -- WHERE-clause cast: api_keys.api_key_id is UUID in the 006_option3
    -- production schema (the only schema where auth_touch_api_key is ever
    -- invoked — community-mode deployments lack license_key_hash so
    -- auth_lookup_api_key never returns a row to feed this function).
    -- The Go caller passes the stringified UUID returned from
    -- auth_lookup_api_key's `k.api_key_id::VARCHAR` projection. Postgres
    -- has no `uuid = character varying` operator, so without a cast this
    -- function errors at every call site.
    --
    -- We cast the PARAMETER to UUID (not both sides to TEXT) so the
    -- WHERE clause uses the api_keys PRIMARY KEY BTREE index on the
    -- UUID column. Casting the column to TEXT would force a sequential
    -- scan on every authenticated request — rejected because the post-auth
    -- fire-and-forget goroutine fires on every successful auth.
    UPDATE api_keys
       SET last_used_at   = NOW(),
           total_requests = total_requests + 1,
           updated_at     = NOW()
     WHERE api_key_id = p_api_key_id::uuid;
END;
$$;

COMMENT ON FUNCTION auth_touch_api_key(VARCHAR) IS
    'SECURITY DEFINER variant of the legacy updateAPIKeyLastUsed UPDATE. '
    'Called from the post-auth fire-and-forget goroutine which has no GUC; '
    'bypasses FORCE RLS on api_keys.';

-- ============================================================================
-- Privilege model: REVOKE PUBLIC + GRANT axonflow_app_role
-- ============================================================================
-- REVOKE EXECUTE FROM PUBLIC runs unconditionally (harmless even on local-dev
-- databases that haven't yet created axonflow_app_role — REVOKE is a no-op if
-- PUBLIC doesn't currently hold the privilege either, and CREATE OR REPLACE's
-- default GRANT TO PUBLIC means the privilege IS held on first run). Putting
-- it inside the role-probe block (mig 104's shape) leaves community-mode
-- databases with PUBLIC EXECUTE on SECURITY DEFINER functions — standard
-- SECURITY DEFINER hardening guidance says default-deny by REVOKE-from-PUBLIC,
-- which we now match.
--
-- GRANT TO axonflow_app_role remains guarded by the role probe: granting to
-- a role that doesn't exist would fail outright. On local-dev installs that
-- haven't run mig 098, the helpers stay installed but unbound until 098 lands.
REVOKE EXECUTE ON FUNCTION auth_lookup_api_key(TEXT)     FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION auth_touch_api_key(VARCHAR)   FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        GRANT  EXECUTE ON FUNCTION auth_lookup_api_key(TEXT)     TO axonflow_app_role;
        GRANT  EXECUTE ON FUNCTION auth_touch_api_key(VARCHAR)   TO axonflow_app_role;

        RAISE NOTICE 'Migration 108: granted EXECUTE on SECURITY DEFINER helpers to axonflow_app_role';
    ELSE
        RAISE NOTICE 'Migration 108: axonflow_app_role not present (mig 098 not yet run); helpers installed but unbound';
    END IF;
END
$$;

-- ============================================================================
-- FORCE RLS branch — only runs when the in-VPC enterprise schema is present
-- ============================================================================
-- Predicates:
--   - `customers` table exists (created by enterprise/100)
--   - `customers.org_id` column exists (created by enterprise/100 line 46)
--   - `api_keys.license_key_hash` column exists (created by the operator-
--     applied 006_option3_auth_system.sql; signals the legacy auth schema
--     is present)
--   - `api_keys.org_id` column exists (created by mig 002 ALTER TABLE)
--
-- All four must hold; if any are missing this is a community-mode database
-- (or a hybrid env mid-migration) and we skip the FORCE branch entirely.
DO $$
DECLARE
    has_customers_table       BOOLEAN;
    has_customers_org_id      BOOLEAN;
    has_api_keys_license_hash BOOLEAN;
    has_api_keys_org_id       BOOLEAN;
    backfilled_api_keys       INTEGER;
    backfilled_customers      INTEGER;
BEGIN
    has_customers_table := EXISTS(
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'customers' AND table_schema = 'public'
    );
    has_customers_org_id := EXISTS(
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'customers' AND column_name = 'org_id' AND table_schema = 'public'
    );
    has_api_keys_license_hash := EXISTS(
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'api_keys' AND column_name = 'license_key_hash' AND table_schema = 'public'
    );
    has_api_keys_org_id := EXISTS(
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'api_keys' AND column_name = 'org_id' AND table_schema = 'public'
    );

    IF NOT (has_customers_table AND has_customers_org_id
            AND has_api_keys_license_hash AND has_api_keys_org_id) THEN
        RAISE NOTICE 'Migration 108: in-VPC enterprise schema not present (customers_table=%, customers_org_id=%, api_keys_license_key_hash=%, api_keys_org_id=%); FORCE RLS branch skipped (community-mode database)',
            has_customers_table, has_customers_org_id, has_api_keys_license_hash, has_api_keys_org_id;
        RETURN;
    END IF;

    -- -----------------------------------------------------------------------
    -- Backfill customers.org_id from customers.organization_id (the surrogate
    -- per-customer identifier seeded by enterprise/100). Idempotent — second
    -- run is a no-op once every row has a non-empty org_id.
    -- -----------------------------------------------------------------------
    UPDATE customers
       SET org_id = organization_id
     WHERE org_id IS NULL OR org_id = '';
    GET DIAGNOSTICS backfilled_customers = ROW_COUNT;
    RAISE NOTICE 'Migration 108: backfilled customers.org_id on % row(s)', backfilled_customers;

    -- -----------------------------------------------------------------------
    -- Backfill api_keys.org_id from the joined customers row. The FK is
    -- api_keys.customer_id -> customers.customer_id (UUID). After the
    -- previous UPDATE, customers.org_id is non-empty for every row.
    -- -----------------------------------------------------------------------
    UPDATE api_keys k
       SET org_id = c.org_id
      FROM customers c
     WHERE k.customer_id = c.customer_id
       AND (k.org_id IS NULL OR k.org_id = '');
    GET DIAGNOSTICS backfilled_api_keys = ROW_COUNT;
    RAISE NOTICE 'Migration 108: backfilled api_keys.org_id on % row(s)', backfilled_api_keys;

    -- -----------------------------------------------------------------------
    -- api_keys — ENABLE + policy + FORCE
    -- -----------------------------------------------------------------------
    EXECUTE 'ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY';

    EXECUTE 'DROP POLICY IF EXISTS api_keys_org_isolation ON api_keys';
    EXECUTE 'CREATE POLICY api_keys_org_isolation ON api_keys
             FOR ALL
             USING (org_id = current_setting(''app.current_org_id'', true))
             WITH CHECK (org_id = current_setting(''app.current_org_id'', true))';

    EXECUTE 'ALTER TABLE api_keys FORCE ROW LEVEL SECURITY';

    -- -----------------------------------------------------------------------
    -- customers — ENABLE + policy + FORCE
    -- -----------------------------------------------------------------------
    EXECUTE 'ALTER TABLE customers ENABLE ROW LEVEL SECURITY';

    EXECUTE 'DROP POLICY IF EXISTS customers_org_id_isolation ON customers';
    EXECUTE 'CREATE POLICY customers_org_id_isolation ON customers
             FOR ALL
             USING (org_id = current_setting(''app.current_org_id'', true))
             WITH CHECK (org_id = current_setting(''app.current_org_id'', true))';

    EXECUTE 'ALTER TABLE customers FORCE ROW LEVEL SECURITY';

    RAISE NOTICE 'Migration 108: FORCE RLS shipped on api_keys + customers (in-VPC enterprise schema detected)';
END
$$;

-- ============================================================================
-- Smoke verification — assert both SECURITY DEFINER functions exist + are
-- SECURITY DEFINER + (conditionally) FORCE RLS state per the NOT EXISTS
-- pattern from mig 102 (mig 101's GROUP BY/COUNT pattern was broken — it
-- silently skipped tables with zero matching policies).
-- ============================================================================
DO $$
DECLARE
    r RECORD;
    expected_funcs TEXT[] := ARRAY['auth_lookup_api_key', 'auth_touch_api_key'];
    fn TEXT;
    has_customers_table       BOOLEAN;
    has_api_keys_license_hash BOOLEAN;
    expected_force_tables     TEXT[];
BEGIN
    -- (1) Assert each function is SECURITY DEFINER.
    FOREACH fn IN ARRAY expected_funcs LOOP
        FOR r IN
            SELECT proname, prosecdef
            FROM pg_proc
            WHERE proname = fn
              AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
        LOOP
            IF NOT r.prosecdef THEN
                RAISE EXCEPTION 'Migration 108 failed: function % is NOT SECURITY DEFINER (prosecdef=false)', r.proname;
            END IF;
            RAISE NOTICE 'Migration 108 verified: % is SECURITY DEFINER', r.proname;
        END LOOP;
    END LOOP;

    -- (2) Assert each expected function exists (NOT EXISTS pattern — see
    --     mig 102 comment block for why GROUP BY/COUNT silently passes when
    --     a function is missing).
    FOR r IN
        SELECT t.fn AS function_name
        FROM unnest(expected_funcs) AS t(fn)
        WHERE NOT EXISTS (
            SELECT 1 FROM pg_proc p
            WHERE p.proname = t.fn
              AND p.pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
        )
    LOOP
        RAISE EXCEPTION 'Migration 108 failed: function % not found in public schema', r.function_name;
    END LOOP;

    -- (3) FORCE RLS smoke — only assert when the in-VPC enterprise schema
    -- is present (matches the gating predicate in the FORCE branch above).
    has_customers_table := EXISTS(
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'customers' AND table_schema = 'public'
    );
    has_api_keys_license_hash := EXISTS(
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'api_keys' AND column_name = 'license_key_hash' AND table_schema = 'public'
    );

    IF NOT (has_customers_table AND has_api_keys_license_hash) THEN
        RAISE NOTICE 'Migration 108: FORCE RLS smoke skipped (community-mode database, no in-VPC enterprise schema)';
        RETURN;
    END IF;

    expected_force_tables := ARRAY['api_keys', 'customers'];

    -- (3a) ENABLE + FORCE state on each expected table.
    FOR r IN
        SELECT relname,
               relrowsecurity AS rls_enabled,
               relforcerowsecurity AS rls_forced
        FROM pg_class
        WHERE relname = ANY(expected_force_tables)
          AND relkind = 'r'
    LOOP
        IF NOT r.rls_enabled THEN
            RAISE EXCEPTION 'Migration 108 failed: RLS not enabled on %', r.relname;
        END IF;
        IF NOT r.rls_forced THEN
            RAISE EXCEPTION 'Migration 108 failed: FORCE RLS not active on %', r.relname;
        END IF;
        RAISE NOTICE 'Migration 108 verified: % (rls_enabled=%, rls_forced=%)',
                     r.relname, r.rls_enabled, r.rls_forced;
    END LOOP;

    -- (3b) NOT EXISTS pattern — each expected table must have an
    -- org_id-isolation policy whose qual references app.current_org_id.
    FOR r IN
        SELECT t.tbl AS table_name
        FROM unnest(expected_force_tables) AS t(tbl)
        WHERE NOT EXISTS (
            SELECT 1 FROM pg_policies p
            WHERE p.tablename = t.tbl
              AND p.qual LIKE '%app.current_org_id%'
        )
    LOOP
        RAISE EXCEPTION 'Migration 108 failed: % has no app.current_org_id isolation policy', r.table_name;
    END LOOP;
END
$$;

COMMIT;
