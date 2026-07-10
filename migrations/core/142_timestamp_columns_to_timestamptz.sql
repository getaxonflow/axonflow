-- Migration 142: retype tz-naive TIMESTAMP columns to TIMESTAMPTZ, and the
-- two SECURITY DEFINER functions whose signatures mirror them
-- Date: 2026-07-09
-- Issue: #2876
--
-- ============================================================================
-- Why this exists
-- ============================================================================
-- gateway_contexts.expires_at was declared TIMESTAMP (no time zone). Postgres
-- silently discards any UTC offset on insert into such a column, storing the
-- raw wall-clock digits as given. The agent computed expires_at via
-- time.Now().Add(ttl) — time.Now() in the process's LOCAL zone — so on a host
-- whose local zone isn't UTC (a dev laptop on PDT, a container inheriting a
-- non-UTC TZ), the stored value ended up hours "behind" the real time: the
-- context read back as already expired the instant it was created. This
-- schema retype is the fix: a TIMESTAMPTZ column preserves whatever offset
-- the Go time.Time carries, so local-zone writers stop corrupting stored
-- instants. The same PR also adds defensive time.Now().UTC() at the
-- local-time write sites (platform/agent/gateway_handlers.go — the one
-- CONFIRMED-live corruption path — plus the AuditQueue entry stamps in
-- platform/agent/audit_queue.go) so the app is correct independent of the
-- column type — but the schema change is what closes the bug class. An audit
-- of every migration in this directory found the same tz-naive declaration on
-- 28 columns across 14 tables (vs. 49 columns elsewhere already correctly
-- TIMESTAMPTZ). On those other columns the bug class is LATENT, not active:
-- today they are populated server-side (DEFAULT CURRENT_TIMESTAMP / SQL
-- NOW() — e.g. the AuditQueue violation INSERT omits created_at entirely,
-- and the one code path that binds a Go entry.Timestamp into
-- agent_audit_logs.timestamp has no live producer), so retyping them here
-- means a future Go-side timestamp write cannot re-introduce the class.
--
-- Two SECURITY DEFINER functions carry a TIMESTAMP parameter/return column
-- that mirrors one of these table columns and must move in lockstep:
--   - promote_deployment_org_license(..., p_expires_at TIMESTAMP DEFAULT NULL)
--     (mig 117) writes organizations.expires_at.
--   - portal_session_lookup(...) RETURNS TABLE(..., expires_at TIMESTAMP)
--     (mig 118) mirrors user_sessions.expires_at; its own header comment
--     already calls out that this type must match exactly since RETURN QUERY
--     enforces a structural type check.
-- These were originally a separate follow-up migration (143), but that split
-- a single logical change across two independent commits: each migration
-- file is its own atomic unit (the runner Execs a whole file in one
-- round-trip, and Postgres implicitly wraps a multi-statement simple-query
-- batch in one transaction — verified empirically: an ALTER TABLE followed by
-- a deliberately-broken statement in the same Exec() call rolls the ALTER
-- back too), but two SEPARATE files are two separate commits with no
-- atomicity between them. Confirmed empirically that the gap is real, not
-- theoretical: with only the column retype applied, calling
-- promote_deployment_org_license the same way the Go agent does (a
-- parameterized time.Time, which arrives as a timestamptz-typed bind
-- parameter) fails to resolve at all —
--   ERROR: function promote_deployment_org_license(varchar, varchar,
--   integer, timestamp with time zone) does not exist
-- because Postgres's function-overload resolution only auto-applies
-- IMPLICIT casts, and timestamp<->timestamptz is only an ASSIGNMENT-context
-- cast (valid for INSERTing into a column, not for matching a call's
-- argument types). So a deploy that landed the column retype but crashed or
-- failed before the function retype would silently break the agent's
-- boot-time license-tier sync (promoteDeploymentOrgTier logs the failure and
-- continues — non-fatal, but broken) until the second migration ran. Both
-- halves are folded into this single file so they commit or roll back
-- together.
--
-- ============================================================================
-- Conversion: USING <col> AT TIME ZONE 'UTC' (pinned, not session TimeZone)
-- ============================================================================
-- Interprets each existing naive value as UTC. The data was written under
-- UTC sessions (confirmed via `SHOW timezone` on this deployment; nothing in
-- docker-compose.yml or config/ overrides it), so for every column populated
-- via DEFAULT CURRENT_TIMESTAMP/NOW() the naive digits ARE the UTC wall
-- clock. Pinning the zone — both here in each USING expression and via
-- SET LOCAL TIME ZONE 'UTC' right after BEGIN — removes the silent-shift
-- footgun of the earlier current_setting('TIMEZONE') formulation: if this
-- file is ever replayed under a non-UTC session (psql with PGTZ set, an RDS
-- parameter-group timezone, a fork's docker-compose override), a
-- session-relative conversion would silently shift every stored instant by
-- the session offset. Equivalent on the happy (UTC-session) path, safe on
-- the unhappy one. For the smaller set of app-supplied columns
-- (gateway_contexts.expires_at, agent_audit_logs.timestamp, and similar),
-- assuming UTC is no-worse-than-before: rows written by non-UTC hosts were
-- already corrupted by the "assume UTC" mismatch at write time, and no SQL
-- expression can recover the true original zone after the fact — retyping
-- only stops FUTURE corruption, it does not repair historical data. Not a
-- blocker; a data-quality note for whoever reads old rows.
--
-- ============================================================================
-- Dependent objects (drop/recreate around the ALTER, same transaction)
-- ============================================================================
-- Postgres refuses ALTER COLUMN ... TYPE on any column a view depends on.
-- Exhaustive dependent-object walk over all 28 columns across every
-- migration category (core, enterprise, industry/{banking,travel},
-- community-saas) plus every inline CREATE VIEW in Go (there are none):
--   - llm_cost_summary (core/020) on llm_call_audits.created_at — present in
--     EVERY deployment mode, dropped/recreated unconditionally below.
--   - sebi_audit_retention_status (industry/banking/300; definition
--     reasserted unchanged by core/127's guarded repair) and
--     mas_audit_retention_status (industry/banking/401), both aggregating
--     policy_violations.created_at — present ONLY where the banking category
--     runs (saas, in-vpc-banking), and only on UPGRADES: 142 sorts before
--     300/401, so on a fresh deploy they don't exist yet when 142 runs.
--     Handled with existence-guarded drop + conditional verbatim recreate in
--     the policy_violations section below.
-- Every other view across all categories either reads none of the 28
-- columns (e.g. audit_retention_summary uses organizations.org_id/name only;
-- active_node_violations uses node_violations + organizations.org_id/name;
-- the sebi/mas/rbi/eu-ai-act compliance-summary views read static_policies
-- only) or sits on tables this migration does not touch. No CHECK
-- constraint, FK, generated column, rule, or RLS policy references any of
-- the 28 columns (RLS policies are all org_id/tenant_id-scoped; the
-- GENERATED columns in industry/banking/301 derive from
-- severity/risk_category/incident_type). Indexes rebuild automatically
-- during ALTER TYPE and are not blockers.
--
-- ============================================================================
-- Cost / locking
-- ============================================================================
-- `ALTER COLUMN ... TYPE ... USING ...` is not a no-op cast here (there's an
-- explicit USING expression), so Postgres performs a full table rewrite under
-- an ACCESS EXCLUSIVE lock, same as migration 133's organization_id retype.
-- Lock hold time scales with each table's total row count. audit_logs is the
-- highest-traffic table in this list (the canonical decision-audit table —
-- writeDecisionAuditLog, /api/v1/decide, portal decisions feed); on a
-- long-lived production deployment with a large audit_logs, plan this
-- migration for a maintenance window. Idempotent: each column is only
-- altered while it still reports data_type = 'timestamp without time zone';
-- the function replacements at the end are unconditionally idempotent
-- (DROP FUNCTION IF EXISTS + CREATE OR REPLACE).
--
-- Wrapped in an explicit transaction: Postgres already treats one Exec()
-- call's ;-separated statements as one implicit transaction with no BEGIN
-- present, but an explicit BEGIN/COMMIT makes that atomicity guarantee
-- visible to a reader instead of resting on an unstated protocol detail.

BEGIN;

-- Pin the session zone for the transaction so nothing in this file — the
-- USING expressions are already pinned to 'UTC', this is belt-and-suspenders
-- for any expression that might consult the session TimeZone — depends on
-- the environment the migration happens to be replayed under.
SET LOCAL TIME ZONE 'UTC';

-- ============================================================================
-- organizations (migration 002)
-- ============================================================================
DO $$
DECLARE
    col text;
BEGIN
    FOREACH col IN ARRAY ARRAY['expires_at', 'created_at', 'updated_at']
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'organizations' AND column_name = col AND data_type = 'timestamp without time zone'
        ) THEN
            EXECUTE format('ALTER TABLE organizations ALTER COLUMN %I TYPE TIMESTAMPTZ USING %I AT TIME ZONE ''UTC''', col, col);
        END IF;
    END LOOP;
END $$;
ALTER TABLE organizations ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE organizations ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;

-- ============================================================================
-- saml_configurations (migration 002)
-- ============================================================================
DO $$
DECLARE
    col text;
BEGIN
    FOREACH col IN ARRAY ARRAY['created_at', 'updated_at']
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'saml_configurations' AND column_name = col AND data_type = 'timestamp without time zone'
        ) THEN
            EXECUTE format('ALTER TABLE saml_configurations ALTER COLUMN %I TYPE TIMESTAMPTZ USING %I AT TIME ZONE ''UTC''', col, col);
        END IF;
    END LOOP;
END $$;
ALTER TABLE saml_configurations ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE saml_configurations ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;

-- ============================================================================
-- api_keys (migration 002)
-- ============================================================================
DO $$
DECLARE
    col text;
BEGIN
    FOREACH col IN ARRAY ARRAY['last_used_at', 'created_at', 'expires_at', 'revoked_at']
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'api_keys' AND column_name = col AND data_type = 'timestamp without time zone'
        ) THEN
            EXECUTE format('ALTER TABLE api_keys ALTER COLUMN %I TYPE TIMESTAMPTZ USING %I AT TIME ZONE ''UTC''', col, col);
        END IF;
    END LOOP;
END $$;
ALTER TABLE api_keys ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;

-- ============================================================================
-- user_sessions (migration 002)
-- ============================================================================
DO $$
DECLARE
    col text;
BEGIN
    FOREACH col IN ARRAY ARRAY['expires_at', 'created_at', 'last_activity_at']
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'user_sessions' AND column_name = col AND data_type = 'timestamp without time zone'
        ) THEN
            EXECUTE format('ALTER TABLE user_sessions ALTER COLUMN %I TYPE TIMESTAMPTZ USING %I AT TIME ZONE ''UTC''', col, col);
        END IF;
    END LOOP;
END $$;
ALTER TABLE user_sessions ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE user_sessions ALTER COLUMN last_activity_at SET DEFAULT CURRENT_TIMESTAMP;

-- ============================================================================
-- grafana_organizations (migration 002)
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'grafana_organizations' AND column_name = 'created_at' AND data_type = 'timestamp without time zone'
    ) THEN
        ALTER TABLE grafana_organizations ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
    END IF;
END $$;
ALTER TABLE grafana_organizations ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;

-- ============================================================================
-- policy_metrics (migration 010)
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'policy_metrics' AND column_name = 'timestamp' AND data_type = 'timestamp without time zone'
    ) THEN
        ALTER TABLE policy_metrics ALTER COLUMN timestamp TYPE TIMESTAMPTZ USING timestamp AT TIME ZONE 'UTC';
    END IF;
END $$;
ALTER TABLE policy_metrics ALTER COLUMN timestamp SET DEFAULT CURRENT_TIMESTAMP;

-- ============================================================================
-- policy_violations (migration 010)
-- ============================================================================
-- Two banking-vertical reporting views aggregate policy_violations.created_at
-- (MIN/MAX plus the retention CASE) and therefore block its ALTER COLUMN
-- TYPE:
--   - sebi_audit_retention_status (industry/banking/300_sebi_ai_ml_templates;
--     core/127's guarded canonicalisation repair reasserts the identical
--     definition on upgraded DBs, so one recreate text serves both)
--   - mas_audit_retention_status (industry/banking/401_mas_feat_templates)
-- They exist ONLY on deployments whose mode includes industry/banking (saas,
-- in-vpc-banking), and only on UPGRADES — 142 sorts before 300/401, so on a
-- fresh deploy neither view exists yet when 142 runs (which is exactly why a
-- fresh-DB CI chain cannot catch this). Guard on existence: drop each view
-- only if present, recreate (verbatim from industry/banking/300/401) only
-- what was dropped, all inside this one transaction so a failure rolls the
-- drops back too.
DO $$
DECLARE
    had_sebi_retention BOOLEAN;
    had_mas_retention  BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM information_schema.views
        WHERE table_schema = 'public' AND table_name = 'sebi_audit_retention_status'
    ) INTO had_sebi_retention;
    SELECT EXISTS (
        SELECT 1 FROM information_schema.views
        WHERE table_schema = 'public' AND table_name = 'mas_audit_retention_status'
    ) INTO had_mas_retention;

    IF had_sebi_retention THEN
        EXECUTE 'DROP VIEW sebi_audit_retention_status';
    END IF;
    IF had_mas_retention THEN
        EXECUTE 'DROP VIEW mas_audit_retention_status';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'policy_violations' AND column_name = 'created_at' AND data_type = 'timestamp without time zone'
    ) THEN
        ALTER TABLE policy_violations ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
    END IF;

    -- Recreated verbatim from industry/banking/300_sebi_ai_ml_templates.sql
    -- (definition identical to core/127's guarded repair).
    IF had_sebi_retention THEN
        EXECUTE $vw$
            CREATE OR REPLACE VIEW sebi_audit_retention_status AS
            SELECT
                sp.policy_id,
                sp.name,
                sp.tenant_id,
                COALESCE((sp.metadata->>'audit_retention_years')::integer, 5) as required_retention_years,
                COUNT(pv.id) as total_violations,
                MIN(pv.created_at) as oldest_violation,
                MAX(pv.created_at) as newest_violation,
                CASE
                    WHEN COUNT(pv.id) = 0 THEN 'NO_VIOLATIONS'
                    WHEN MIN(pv.created_at) > NOW() - INTERVAL '5 years' THEN 'COMPLIANT'
                    ELSE 'REVIEW_REQUIRED'
                END as retention_status
            FROM static_policies sp
            LEFT JOIN policy_violations pv ON pv.violation_type = sp.policy_id
            WHERE sp.category IN ('compliance-sebi', 'pii_detection')
              AND (
                  (sp.metadata->>'compliance_framework') LIKE '%SEBI%'
                  OR (sp.metadata->>'compliance_framework') LIKE '%DPDP%'
              )
            GROUP BY sp.policy_id, sp.name, sp.tenant_id, (sp.metadata->>'audit_retention_years')
            ORDER BY sp.policy_id
        $vw$;
    END IF;

    -- Recreated verbatim from industry/banking/401_mas_feat_templates.sql.
    IF had_mas_retention THEN
        EXECUTE $vw$
            CREATE OR REPLACE VIEW mas_audit_retention_status AS
            SELECT
                sp.policy_id,
                sp.name,
                sp.tenant_id,
                COALESCE((sp.metadata->>'audit_retention_years')::integer, 7) as required_retention_years,
                COUNT(pv.id) as total_violations,
                MIN(pv.created_at) as oldest_violation,
                MAX(pv.created_at) as newest_violation,
                CASE
                    WHEN COUNT(pv.id) = 0 THEN 'NO_VIOLATIONS'
                    WHEN MIN(pv.created_at) > NOW() - INTERVAL '7 years' THEN 'COMPLIANT'
                    ELSE 'REVIEW_REQUIRED'
                END as retention_status
            FROM static_policies sp
            LEFT JOIN policy_violations pv ON pv.violation_type = sp.policy_id
            WHERE (sp.metadata->>'compliance_framework') LIKE '%MAS%'
            GROUP BY sp.policy_id, sp.name, sp.tenant_id, (sp.metadata->>'audit_retention_years')
            ORDER BY sp.policy_id
        $vw$;
    END IF;
END $$;
ALTER TABLE policy_violations ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;

-- ============================================================================
-- agent_audit_logs (migration 011) — LATENT instance of the bug class: the
-- AuditQueue AuditTypeAudit branch binds a Go entry.Timestamp into this
-- column, but that branch has no live producer today (see the header note);
-- retyped so a future producer cannot corrupt it. Its sibling
-- orchestrator_audit_logs.timestamp (same migration file) is already
-- TIMESTAMPTZ.
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'agent_audit_logs' AND column_name = 'timestamp' AND data_type = 'timestamp without time zone'
    ) THEN
        ALTER TABLE agent_audit_logs ALTER COLUMN timestamp TYPE TIMESTAMPTZ USING timestamp AT TIME ZONE 'UTC';
    END IF;
END $$;
ALTER TABLE agent_audit_logs ALTER COLUMN timestamp SET DEFAULT CURRENT_TIMESTAMP;

-- ============================================================================
-- connectors (migration 012)
-- ============================================================================
DO $$
DECLARE
    col text;
BEGIN
    FOREACH col IN ARRAY ARRAY['installed_at', 'last_health_check']
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'connectors' AND column_name = col AND data_type = 'timestamp without time zone'
        ) THEN
            EXECUTE format('ALTER TABLE connectors ALTER COLUMN %I TYPE TIMESTAMPTZ USING %I AT TIME ZONE ''UTC''', col, col);
        END IF;
    END LOOP;
END $$;
ALTER TABLE connectors ALTER COLUMN installed_at SET DEFAULT NOW();

-- ============================================================================
-- gateway_contexts (migration 020) — expires_at is the confirmed bug this
-- issue started from. This retype is the fix; the same PR also adds a
-- defensive time.Now().UTC() at the write site in
-- platform/agent/gateway_handlers.go (belt-and-suspenders).
-- ============================================================================
DO $$
DECLARE
    col text;
BEGIN
    FOREACH col IN ARRAY ARRAY['expires_at', 'created_at']
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'gateway_contexts' AND column_name = col AND data_type = 'timestamp without time zone'
        ) THEN
            EXECUTE format('ALTER TABLE gateway_contexts ALTER COLUMN %I TYPE TIMESTAMPTZ USING %I AT TIME ZONE ''UTC''', col, col);
        END IF;
    END LOOP;
END $$;
ALTER TABLE gateway_contexts ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;

-- ============================================================================
-- llm_call_audits (migration 020)
-- ============================================================================
-- llm_cost_summary (migration 020) is a view over llm_call_audits.created_at
-- (DATE_TRUNC('day', created_at) grouping) — Postgres refuses ALTER COLUMN
-- TYPE while a view depends on the column, so drop and recreate it around the
-- ALTER. Definition copied verbatim from 020_gateway_mode_audit.sql.
DROP VIEW IF EXISTS llm_cost_summary;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'llm_call_audits' AND column_name = 'created_at' AND data_type = 'timestamp without time zone'
    ) THEN
        ALTER TABLE llm_call_audits ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
    END IF;
END $$;
ALTER TABLE llm_call_audits ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;
CREATE OR REPLACE VIEW llm_cost_summary AS
SELECT
    client_id,
    provider,
    model,
    DATE_TRUNC('day', created_at) AS date,
    COUNT(*) AS call_count,
    SUM(prompt_tokens) AS total_prompt_tokens,
    SUM(completion_tokens) AS total_completion_tokens,
    SUM(total_tokens) AS total_tokens,
    SUM(estimated_cost_usd) AS total_cost_usd,
    AVG(latency_ms) AS avg_latency_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95_latency_ms
FROM llm_call_audits
GROUP BY client_id, provider, model, DATE_TRUNC('day', created_at);
COMMENT ON VIEW llm_cost_summary IS 'Daily summary of LLM costs by client, provider, and model';

-- ============================================================================
-- evidence_exports (migration 056)
-- ============================================================================
DO $$
DECLARE
    col text;
BEGIN
    FOREACH col IN ARRAY ARRAY['date_range_start', 'date_range_end', 'created_at']
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'evidence_exports' AND column_name = col AND data_type = 'timestamp without time zone'
        ) THEN
            EXECUTE format('ALTER TABLE evidence_exports ALTER COLUMN %I TYPE TIMESTAMPTZ USING %I AT TIME ZONE ''UTC''', col, col);
        END IF;
    END LOOP;
END $$;
ALTER TABLE evidence_exports ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;

-- ============================================================================
-- audit_logs (migration 059) — the canonical decision-audit table
-- (writeDecisionAuditLog, /api/v1/decide, portal decisions feed). Highest
-- expected row count of any table in this migration; see locking note above.
-- ============================================================================
DO $$
DECLARE
    col text;
BEGIN
    FOREACH col IN ARRAY ARRAY['timestamp', 'created_at']
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'audit_logs' AND column_name = col AND data_type = 'timestamp without time zone'
        ) THEN
            EXECUTE format('ALTER TABLE audit_logs ALTER COLUMN %I TYPE TIMESTAMPTZ USING %I AT TIME ZONE ''UTC''', col, col);
        END IF;
    END LOOP;
END $$;
ALTER TABLE audit_logs ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;

-- ============================================================================
-- tenants (migration 062)
-- ============================================================================
DO $$
DECLARE
    col text;
BEGIN
    FOREACH col IN ARRAY ARRAY['created_at', 'updated_at']
    LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'tenants' AND column_name = col AND data_type = 'timestamp without time zone'
        ) THEN
            EXECUTE format('ALTER TABLE tenants ALTER COLUMN %I TYPE TIMESTAMPTZ USING %I AT TIME ZONE ''UTC''', col, col);
        END IF;
    END LOOP;
END $$;
ALTER TABLE tenants ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE tenants ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;

-- ============================================================================
-- promote_deployment_org_license (migration 117) — p_expires_at mirrors
-- organizations.expires_at, retyped above in this same transaction.
-- CREATE OR REPLACE FUNCTION cannot change an argument type — Postgres would
-- treat TIMESTAMPTZ as a new overload and leave the old TIMESTAMP-typed
-- function alongside it — so the old signature is DROPped first. Body,
-- comments, and REVOKE/GRANT posture copied verbatim from 117 with only the
-- TIMESTAMP -> TIMESTAMPTZ type swapped.
-- ============================================================================
DROP FUNCTION IF EXISTS promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMP);

CREATE OR REPLACE FUNCTION promote_deployment_org_license(
    p_org_id     VARCHAR(255),
    p_tier       VARCHAR(50),
    p_max_nodes  INTEGER,
    p_expires_at TIMESTAMPTZ DEFAULT NULL
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'organizations'
    ) THEN
        INSERT INTO organizations (org_id, name, tier, max_nodes, license_key, expires_at)
        VALUES (p_org_id, p_org_id, p_tier, p_max_nodes, '', p_expires_at)
        ON CONFLICT (org_id) DO UPDATE SET
            tier       = EXCLUDED.tier,
            max_nodes  = EXCLUDED.max_nodes,
            expires_at = EXCLUDED.expires_at,
            updated_at = CURRENT_TIMESTAMP
        WHERE organizations.tier       IS DISTINCT FROM EXCLUDED.tier
           OR organizations.max_nodes  IS DISTINCT FROM EXCLUDED.max_nodes
           OR organizations.expires_at IS DISTINCT FROM EXCLUDED.expires_at;
    END IF;
END;
$$;

COMMENT ON FUNCTION promote_deployment_org_license IS
    'SECURITY DEFINER upsert that promotes the deployment org''s organizations '
    'row to its licensed tier/max_nodes/expires_at. Bypasses FORCE RLS on '
    'organizations (mig 103) for the agent boot-time license-tier sync (#2535). '
    'Mirrors register_org (mig 104) with an added expires_at column. '
    'p_expires_at is TIMESTAMPTZ as of mig 142 (#2876).';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE EXECUTE ON FUNCTION promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ) FROM PUBLIC;
        GRANT  EXECUTE ON FUNCTION promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ) TO axonflow_app_role;
        RAISE NOTICE 'Migration 142: granted EXECUTE on promote_deployment_org_license to axonflow_app_role';
    ELSE
        RAISE NOTICE 'Migration 142: axonflow_app_role not present (mig 098 not yet run on this DB); promote_deployment_org_license installed but unbound';
    END IF;
END
$$;

DO $$
DECLARE
    v_secdef BOOLEAN;
BEGIN
    SELECT prosecdef INTO v_secdef
    FROM pg_proc
    WHERE proname = 'promote_deployment_org_license'
      AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');

    IF v_secdef IS NULL THEN
        RAISE EXCEPTION 'Migration 142 failed: promote_deployment_org_license not found in public schema';
    END IF;
    IF NOT v_secdef THEN
        RAISE EXCEPTION 'Migration 142 failed: promote_deployment_org_license is NOT SECURITY DEFINER (prosecdef=false)';
    END IF;
    RAISE NOTICE 'Migration 142 verified: promote_deployment_org_license is SECURITY DEFINER';
END
$$;

-- ============================================================================
-- portal_session_lookup (migration 118) — expires_at mirrors
-- user_sessions.expires_at, retyped above in this same transaction. A
-- RETURNS TABLE shape change also requires DROP FUNCTION before CREATE OR
-- REPLACE (same rule as an argument-type change). Body, comments, and
-- REVOKE/GRANT posture copied verbatim from 118 with only the
-- TIMESTAMP -> TIMESTAMPTZ type swapped.
-- ============================================================================
DROP FUNCTION IF EXISTS portal_session_lookup(VARCHAR);

CREATE OR REPLACE FUNCTION portal_session_lookup(p_session_id VARCHAR)
    -- Column types MUST match user_sessions exactly (RETURN QUERY enforces a
    -- structural type check): org_id/tenant_id/user_email/user_name are
    -- VARCHAR(255); expires_at is TIMESTAMPTZ as of mig 142 (#2876).
    RETURNS TABLE(
        org_id     VARCHAR,
        tenant_id  VARCHAR,
        user_email VARCHAR,
        user_name  VARCHAR,
        expires_at TIMESTAMPTZ
    )
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT s.org_id, s.tenant_id, s.user_email, s.user_name, s.expires_at
    FROM user_sessions s
    WHERE s.session_id = p_session_id;
END;
$$;

COMMENT ON FUNCTION portal_session_lookup IS
    'SECURITY DEFINER pre-auth session lookup. Bypasses RLS on user_sessions '
    'for the AuthMiddleware session-resolution path, which runs before any '
    'org GUC can be set (the lookup is what establishes the org). Returns '
    'only the columns the middleware needs, never the full row. See mig 104 '
    'for the equivalent HandleLogin org-credential helper. expires_at is '
    'TIMESTAMPTZ as of mig 142 (#2876).';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE EXECUTE ON FUNCTION portal_session_lookup(VARCHAR) FROM PUBLIC;
        GRANT  EXECUTE ON FUNCTION portal_session_lookup(VARCHAR) TO axonflow_app_role;
        RAISE NOTICE 'Migration 142: granted EXECUTE on portal_session_lookup to axonflow_app_role';
    ELSE
        RAISE NOTICE 'Migration 142: axonflow_app_role not present (mig 098 not yet run); portal_session_lookup installed but unbound';
    END IF;
END
$$;

DO $$
DECLARE
    r RECORD;
BEGIN
    SELECT proname, prosecdef INTO r
    FROM pg_proc
    WHERE proname = 'portal_session_lookup'
      AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Migration 142 failed: portal_session_lookup not created';
    END IF;
    IF NOT r.prosecdef THEN
        RAISE EXCEPTION 'Migration 142 failed: portal_session_lookup is NOT SECURITY DEFINER (prosecdef=false)';
    END IF;
    RAISE NOTICE 'Migration 142 verified: portal_session_lookup is SECURITY DEFINER';
END
$$;

COMMIT;
