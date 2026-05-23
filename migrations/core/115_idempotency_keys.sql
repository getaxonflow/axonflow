-- Migration 115: idempotency_keys table for safe Retry-on-Fail semantics
--
-- Stores cached responses keyed by (Idempotency-Key, tenant_id, endpoint) so
-- a workflow node that retries the same request body within TTL gets back the
-- original response byte-for-byte — no double row creation, no double audit
-- record, no double policy-engine work.
--
-- Consumed by platform/shared/idempotency.Store. Wired into the agent's
-- /api/v1/mcp/check-input + /api/v1/hitl/queue handlers and the orchestrator's
-- /api/v1/audit/tool-call handler.
--
-- RLS posture: ENABLE + FORCE. tenant_id is the isolation key. The middleware
-- always queries with WithOrgAndTenantScope so app.current_tenant_id matches
-- the row's tenant_id, mirroring the v9 Phase 8 wrap convention.

CREATE TABLE IF NOT EXISTS idempotency_keys (
    key TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    response_body BYTEA NOT NULL,
    status_code INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (key, tenant_id, endpoint)
);

CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expires_at
    ON idempotency_keys (expires_at);

ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON idempotency_keys;
CREATE POLICY tenant_isolation ON idempotency_keys
    USING (tenant_id = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true));

COMMENT ON TABLE idempotency_keys IS
    'Cached responses for HTTP Idempotency-Key dedup. TTL ~24h, swept by background job.';
