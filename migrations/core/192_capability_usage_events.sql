-- Capability usage stays in the canonical usage_events stream. These rows are
-- advisory telemetry, not billed usage: unknown cost must remain SQL NULL.
-- Fail rather than wait behind a long writer with an ACCESS EXCLUSIVE lock.
-- This migration does only metadata changes; the index scan is in core/193.
SET LOCAL lock_timeout = '5s';
ALTER TABLE usage_events
    ADD COLUMN IF NOT EXISTS capability_tenant_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS capability_event_key VARCHAR(255),
    ADD COLUMN IF NOT EXISTS capability_name VARCHAR(100),
    ADD COLUMN IF NOT EXISTS capability_status VARCHAR(50),
    ADD COLUMN IF NOT EXISTS capability_cost_status VARCHAR(50),
    ADD COLUMN IF NOT EXISTS capability_outcome_status VARCHAR(50),
    ADD COLUMN IF NOT EXISTS capability_digest CHAR(64);

-- NOT VALID avoids a full scan of the existing time-series table during
-- rollout while still enforcing every new write.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'capability_usage_shape') THEN
        ALTER TABLE usage_events ADD CONSTRAINT capability_usage_shape CHECK (
            (LEFT(event_type, 11) <> 'capability_' AND capability_event_key IS NULL)
            OR (event_type IN ('capability_source_read','capability_model_usage',
                               'capability_preview','capability_invocation','capability_outcome')
                AND capability_event_key ~ '^[0-9a-f]{64}$'
                AND capability_event_key IS NOT NULL
                AND capability_tenant_id IS NOT NULL
                AND capability_name IS NOT NULL
                AND capability_status IS NOT NULL
                AND capability_cost_status IS NOT NULL
                AND capability_outcome_status IS NOT NULL
                AND capability_outcome_status = 'not_measured'
                AND capability_digest ~ '^[0-9a-f]{64}$'
                AND capability_digest IS NOT NULL
                AND estimated_cost_cents IS NULL)
        ) NOT VALID;
    END IF;
END $$;

-- Existing usage events remain org scoped. Capability rows additionally need
-- a verified tenant scope, even for a second tenant in the same organization.
DROP POLICY IF EXISTS capability_usage_tenant_guard ON usage_events;
CREATE POLICY capability_usage_tenant_guard ON usage_events AS RESTRICTIVE
    USING (LEFT(event_type, 11) <> 'capability_' OR
           (capability_tenant_id IS NOT NULL AND
            capability_tenant_id = current_setting('app.current_tenant_id', true)))
    WITH CHECK (LEFT(event_type, 11) <> 'capability_' OR
                (capability_tenant_id IS NOT NULL AND
                 capability_tenant_id = current_setting('app.current_tenant_id', true)));

-- core/098 grants app_role UPDATE and DELETE on all existing tables. Keep
-- legacy usage CRUD intact, but make capability evidence append-only to that
-- role so it cannot erase or rewrite a digest before replay. Platform admin
-- cleanup retains BYPASSRLS authority.
DROP POLICY IF EXISTS capability_usage_immutable_update ON usage_events;
CREATE POLICY capability_usage_immutable_update ON usage_events AS RESTRICTIVE
    FOR UPDATE USING (capability_event_key IS NULL)
    WITH CHECK (capability_event_key IS NULL);
DROP POLICY IF EXISTS capability_usage_immutable_delete ON usage_events;
CREATE POLICY capability_usage_immutable_delete ON usage_events AS RESTRICTIVE
    FOR DELETE USING (capability_event_key IS NULL);

-- The legacy hourly/daily billing rollups have non-null cost totals. Keep
-- advisory capability events out until a status-aware rollup is introduced.
CREATE OR REPLACE FUNCTION aggregate_usage_hourly(
    p_start_time TIMESTAMP WITH TIME ZONE,
    p_end_time TIMESTAMP WITH TIME ZONE
) RETURNS INTEGER AS $$
DECLARE
    aggregated_count INTEGER := 0;
BEGIN
    INSERT INTO usage_hourly (
        org_id, client_id, event_type, hour_bucket,
        event_count, total_tokens, prompt_tokens, completion_tokens,
        total_cost_cents, avg_latency_ms,
        total_policies_evaluated, total_policy_violations,
        success_count, error_count
    )
    SELECT org_id, client_id, event_type, DATE_TRUNC('hour', created_at),
        COUNT(*), SUM(total_tokens), SUM(prompt_tokens), SUM(completion_tokens),
        SUM(estimated_cost_cents), AVG(latency_ms)::INTEGER,
        SUM(policies_evaluated), SUM(policy_violations),
        SUM(CASE WHEN http_status_code < 400 THEN 1 ELSE 0 END),
        SUM(CASE WHEN http_status_code >= 400 THEN 1 ELSE 0 END)
    FROM usage_events
    WHERE created_at >= p_start_time AND created_at < p_end_time
      AND LEFT(event_type, 11) <> 'capability_'
    GROUP BY org_id, client_id, event_type, DATE_TRUNC('hour', created_at)
    ON CONFLICT (org_id, COALESCE(client_id, ''), event_type, hour_bucket)
    DO UPDATE SET
        event_count = EXCLUDED.event_count,
        total_tokens = EXCLUDED.total_tokens,
        prompt_tokens = EXCLUDED.prompt_tokens,
        completion_tokens = EXCLUDED.completion_tokens,
        total_cost_cents = EXCLUDED.total_cost_cents,
        avg_latency_ms = EXCLUDED.avg_latency_ms,
        total_policies_evaluated = EXCLUDED.total_policies_evaluated,
        total_policy_violations = EXCLUDED.total_policy_violations,
        success_count = EXCLUDED.success_count,
        error_count = EXCLUDED.error_count,
        updated_at = NOW();
    GET DIAGNOSTICS aggregated_count = ROW_COUNT;
    RETURN aggregated_count;
END;
$$ LANGUAGE plpgsql;
