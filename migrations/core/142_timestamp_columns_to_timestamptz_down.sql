-- Down migration 142: revert the 28 TIMESTAMPTZ columns back to TIMESTAMP,
-- and promote_deployment_org_license / portal_session_lookup back to their
-- TIMESTAMP-typed signatures.
-- Issue: #2876
--
-- USING <col> AT TIME ZONE 'UTC' converts each absolute instant back to a
-- naive UTC timestamp — pinned to the same zone the up migration used, so it
-- exactly reverses the up conversion regardless of what session TimeZone the
-- file is replayed under (SET LOCAL TIME ZONE 'UTC' below is
-- belt-and-suspenders for the same reason; see the up migration's header).
-- Idempotent: each column is only altered while it still reports data_type =
-- 'timestamp with time zone'; the function reverts are unconditionally
-- idempotent (DROP FUNCTION IF EXISTS + CREATE OR REPLACE). Purely
-- structural — does not attempt to restore the pre-fix DEFAULT expressions
-- (SET DEFAULT CURRENT_TIMESTAMP is correct for either column type).
--
-- Wrapped in one transaction (see migration 142's header for why the two
-- halves — column retypes and function signatures — must commit or roll
-- back together, not as separate migrations).
--
-- Dependent views block the reverse ALTERs exactly as they did going up:
--   - llm_cost_summary (core/020) on llm_call_audits.created_at — present
--     everywhere; dropped before the loop, recreated after.
--   - sebi_audit_retention_status (industry/banking/300) and
--     mas_audit_retention_status (industry/banking/401) on
--     policy_violations.created_at — banking-mode only; handled in a
--     dedicated existence-guarded block (mirror of the up migration's),
--     which is also why policy_violations is absent from the pairs loop.
--
-- api_keys is also absent from the pairs loop: its revert is gated on the
-- schema variant (see the dedicated block below) because the in-VPC option3
-- api_keys schema is natively TIMESTAMPTZ and must not be flipped to naive
-- by a rollback of a conversion that never touched it.

BEGIN;

SET LOCAL TIME ZONE 'UTC';

DROP FUNCTION IF EXISTS promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ);

CREATE OR REPLACE FUNCTION promote_deployment_org_license(
    p_org_id     VARCHAR(255),
    p_tier       VARCHAR(50),
    p_max_nodes  INTEGER,
    p_expires_at TIMESTAMP DEFAULT NULL
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
    'Mirrors register_org (mig 104) with an added expires_at column.';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE EXECUTE ON FUNCTION promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMP) FROM PUBLIC;
        GRANT  EXECUTE ON FUNCTION promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMP) TO axonflow_app_role;
    END IF;
END
$$;

DROP FUNCTION IF EXISTS portal_session_lookup(VARCHAR);

CREATE OR REPLACE FUNCTION portal_session_lookup(p_session_id VARCHAR)
    RETURNS TABLE(
        org_id     VARCHAR,
        tenant_id  VARCHAR,
        user_email VARCHAR,
        user_name  VARCHAR,
        expires_at TIMESTAMP
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
    'for the equivalent HandleLogin org-credential helper.';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role') THEN
        REVOKE EXECUTE ON FUNCTION portal_session_lookup(VARCHAR) FROM PUBLIC;
        GRANT  EXECUTE ON FUNCTION portal_session_lookup(VARCHAR) TO axonflow_app_role;
    END IF;
END
$$;

DROP VIEW IF EXISTS llm_cost_summary;

-- policy_violations (migration 010) — mirror of the up migration's guarded
-- block: sebi_audit_retention_status (industry/banking/300) and
-- mas_audit_retention_status (industry/banking/401) aggregate
-- policy_violations.created_at and block the reverse ALTER on banking-mode
-- deployments. Drop each only if present, recreate (verbatim) only what was
-- dropped, inside this same transaction.
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
        WHERE table_name = 'policy_violations' AND column_name = 'created_at' AND data_type = 'timestamp with time zone'
    ) THEN
        ALTER TABLE policy_violations ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
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

-- api_keys (migration 002) — reverted only on the migration-002 schema
-- variant. Two api_keys schemas exist in the wild: core/002's (id, org_id,
-- key_hash, key_prefix, ... — tz-naive TIMESTAMP, what the up migration
-- converts) and the operator-managed in-VPC option3 schema
-- (platform/database/migrations/006_option3_auth_system.sql: api_key_id,
-- customer_id, license_key_hash, ... — natively TIMESTAMPTZ, which the up
-- migration therefore never touched). A blanket tz-guarded revert cannot
-- tell "converted by the up" apart from "always tz-aware": it would flip the
-- option3 columns to a naive state they never had, and auth_lookup_api_key
-- (core/108) declares expires_at/revoked_at/last_used_at TIMESTAMPTZ in its
-- RETURNS TABLE — RETURN QUERY's structural type check would then error on
-- every license validation. Gate on the option3 discriminator column
-- (license_key_hash), the same schema probe core/108 uses.
DO $$
DECLARE
    col text;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'api_keys' AND column_name = 'license_key_hash'
    ) THEN
        FOREACH col IN ARRAY ARRAY['last_used_at', 'created_at', 'expires_at', 'revoked_at']
        LOOP
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'api_keys' AND column_name = col AND data_type = 'timestamp with time zone'
            ) THEN
                EXECUTE format('ALTER TABLE api_keys ALTER COLUMN %I TYPE TIMESTAMP USING %I AT TIME ZONE ''UTC''', col, col);
            END IF;
        END LOOP;
    END IF;
END $$;

DO $$
DECLARE
    tbl text;
    col text;
    pairs text[][] := ARRAY[
        ARRAY['organizations', 'expires_at'],
        ARRAY['organizations', 'created_at'],
        ARRAY['organizations', 'updated_at'],
        ARRAY['saml_configurations', 'created_at'],
        ARRAY['saml_configurations', 'updated_at'],
        ARRAY['user_sessions', 'expires_at'],
        ARRAY['user_sessions', 'created_at'],
        ARRAY['user_sessions', 'last_activity_at'],
        ARRAY['grafana_organizations', 'created_at'],
        ARRAY['policy_metrics', 'timestamp'],
        ARRAY['agent_audit_logs', 'timestamp'],
        ARRAY['connectors', 'installed_at'],
        ARRAY['connectors', 'last_health_check'],
        ARRAY['gateway_contexts', 'expires_at'],
        ARRAY['gateway_contexts', 'created_at'],
        ARRAY['llm_call_audits', 'created_at'],
        ARRAY['evidence_exports', 'date_range_start'],
        ARRAY['evidence_exports', 'date_range_end'],
        ARRAY['evidence_exports', 'created_at'],
        ARRAY['audit_logs', 'timestamp'],
        ARRAY['audit_logs', 'created_at'],
        ARRAY['tenants', 'created_at'],
        ARRAY['tenants', 'updated_at']
    ];
    pair text[];
BEGIN
    FOREACH pair SLICE 1 IN ARRAY pairs
    LOOP
        tbl := pair[1];
        col := pair[2];
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = tbl AND column_name = col AND data_type = 'timestamp with time zone'
        ) THEN
            EXECUTE format('ALTER TABLE %I ALTER COLUMN %I TYPE TIMESTAMP USING %I AT TIME ZONE ''UTC''', tbl, col, col);
        END IF;
    END LOOP;
END $$;

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

COMMIT;
