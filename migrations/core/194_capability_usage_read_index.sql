-- One statement per migration file permits an online build under the agent
-- runner. Fail closed on an invalid index left by a failed concurrent build.
CREATE INDEX CONCURRENTLY idx_usage_events_capability_tenant_window
    ON usage_events (org_id, capability_tenant_id, capability_name, created_at DESC)
    WHERE capability_event_key IS NOT NULL;
