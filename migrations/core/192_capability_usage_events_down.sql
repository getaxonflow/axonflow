-- Reject a downgrade that would strip tenant keys and cost status from live
-- advisory rows, making them visible or billable as legacy usage.
DO $$ BEGIN
    -- A non-BYPASSRLS migrator must error instead of seeing a filtered zero.
    PERFORM set_config('row_security', 'off', true);
    IF EXISTS (SELECT 1 FROM usage_events WHERE capability_event_key IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot downgrade capability usage while events exist';
    END IF;
END $$;
DROP POLICY IF EXISTS capability_usage_tenant_guard ON usage_events;
DROP POLICY IF EXISTS capability_usage_immutable_update ON usage_events;
DROP POLICY IF EXISTS capability_usage_immutable_delete ON usage_events;
DROP INDEX IF EXISTS ux_usage_events_capability_key;
ALTER TABLE usage_events DROP CONSTRAINT IF EXISTS capability_usage_shape;
ALTER TABLE usage_events
    DROP COLUMN IF EXISTS capability_tenant_id,
    DROP COLUMN IF EXISTS capability_event_key,
    DROP COLUMN IF EXISTS capability_name,
    DROP COLUMN IF EXISTS capability_status,
    DROP COLUMN IF EXISTS capability_cost_status,
    DROP COLUMN IF EXISTS capability_outcome_status,
    DROP COLUMN IF EXISTS capability_digest;
-- Restore enterprise/126's idempotent hourly rollup. Core-only deployments
-- also retain safe overwrite semantics after rollback.
CREATE OR REPLACE FUNCTION aggregate_usage_hourly(
    p_start_time TIMESTAMP WITH TIME ZONE,
    p_end_time TIMESTAMP WITH TIME ZONE
)
RETURNS INTEGER AS $$
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
    SELECT
        org_id,
        client_id,
        event_type,
        DATE_TRUNC('hour', created_at) as hour_bucket,
        COUNT(*) as event_count,
        SUM(total_tokens) as total_tokens,
        SUM(prompt_tokens) as prompt_tokens,
        SUM(completion_tokens) as completion_tokens,
        SUM(estimated_cost_cents) as total_cost_cents,
        AVG(latency_ms)::INTEGER as avg_latency_ms,
        SUM(policies_evaluated) as total_policies_evaluated,
        SUM(policy_violations) as total_policy_violations,
        SUM(CASE WHEN http_status_code < 400 THEN 1 ELSE 0 END) as success_count,
        SUM(CASE WHEN http_status_code >= 400 THEN 1 ELSE 0 END) as error_count
    FROM usage_events
    WHERE created_at >= p_start_time
      AND created_at <  p_end_time
    GROUP BY org_id, client_id, event_type, DATE_TRUNC('hour', created_at)
    ON CONFLICT (org_id, COALESCE(client_id, ''), event_type, hour_bucket)
    DO UPDATE SET
        event_count              = EXCLUDED.event_count,
        total_tokens             = EXCLUDED.total_tokens,
        prompt_tokens            = EXCLUDED.prompt_tokens,
        completion_tokens        = EXCLUDED.completion_tokens,
        total_cost_cents         = EXCLUDED.total_cost_cents,
        avg_latency_ms           = EXCLUDED.avg_latency_ms,
        total_policies_evaluated = EXCLUDED.total_policies_evaluated,
        total_policy_violations  = EXCLUDED.total_policy_violations,
        success_count            = EXCLUDED.success_count,
        error_count              = EXCLUDED.error_count,
        updated_at               = NOW();

    GET DIAGNOSTICS aggregated_count = ROW_COUNT;
    RETURN aggregated_count;
END;
$$ LANGUAGE plpgsql;
