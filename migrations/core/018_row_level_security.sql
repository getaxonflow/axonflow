-- Migration 017: Row-Level Security (RLS) for Multi-Tenant Data Isolation
-- Date: 2025-11-20
-- Purpose: Enable RLS on all multi-tenant tables (all have org_id from CREATE TABLE)

-- Helper functions for RLS
CREATE OR REPLACE FUNCTION get_current_org_id() RETURNS TEXT AS $$
BEGIN
    RETURN current_setting('app.current_org_id', TRUE);
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION set_org_id(org_id_value TEXT) RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_org_id', org_id_value, FALSE);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION reset_org_id() RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_org_id', '', FALSE);
END;
$$ LANGUAGE plpgsql;

-- Enable RLS on all multi-tenant tables
-- Note: Some tables are enterprise-only and may not exist in OSS builds
DO $$
DECLARE
    tables_with_org_id text[] := ARRAY[
        'customers', 'usage_metrics', 'request_log',
        'agent_audit_logs', 'orchestrator_audit_logs',
        'connectors',
        'static_policies', 'dynamic_policies', 'policy_evaluation_cache',
        'policy_metrics', 'policy_violations',
        'service_identities', 'license_keys',
        'marketplace_usage_records',
        'organizations', 'saml_configurations', 'api_keys', 'user_sessions',
        'grafana_organizations', 'agent_heartbeats', 'node_violations',
        'usage_events', 'usage_hourly', 'usage_daily', 'usage_monthly',
        'customer_portal_api_keys'
    ];
    tbl_name text;
    table_exists boolean;
    enabled_count integer := 0;
BEGIN
    FOREACH tbl_name IN ARRAY tables_with_org_id
    LOOP
        -- Check if table exists before enabling RLS
        SELECT EXISTS (
            SELECT 1 FROM information_schema.tables t
            WHERE t.table_schema = 'public' AND t.table_name = tbl_name
        ) INTO table_exists;

        IF NOT table_exists THEN
            RAISE NOTICE 'Skipping RLS for table % (does not exist - enterprise-only)', tbl_name;
            CONTINUE;
        END IF;

        -- Enable RLS
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl_name);

        -- Create policies (use IF NOT EXISTS to be idempotent)
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_select ON %I', tbl_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_insert ON %I', tbl_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_update ON %I', tbl_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation_delete ON %I', tbl_name);

        EXECUTE format('CREATE POLICY tenant_isolation_select ON %I FOR SELECT USING (org_id = get_current_org_id())', tbl_name);
        EXECUTE format('CREATE POLICY tenant_isolation_insert ON %I FOR INSERT WITH CHECK (org_id = get_current_org_id())', tbl_name);
        EXECUTE format('CREATE POLICY tenant_isolation_update ON %I FOR UPDATE USING (org_id = get_current_org_id())', tbl_name);
        EXECUTE format('CREATE POLICY tenant_isolation_delete ON %I FOR DELETE USING (org_id = get_current_org_id())', tbl_name);

        RAISE NOTICE 'Enabled RLS on table: %', tbl_name;
        enabled_count := enabled_count + 1;
    END LOOP;

    RAISE NOTICE 'RLS enabled on % tables', enabled_count;
END $$;

-- Log completion
DO $$
BEGIN
    RAISE NOTICE 'Migration 018 completed. RLS enabled on available tables (enterprise tables skipped if not present).';
END $$;
