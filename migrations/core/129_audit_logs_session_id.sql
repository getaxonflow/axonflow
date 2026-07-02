-- Migration 129: Per-session identity on the canonical audit_logs
-- Date: 2026-07-01
-- Purpose: Add a first-class session_id column to the canonical decision row
--          (audit_logs) so a governed request can be attributed to the AI-tool
--          session that produced it (Claude Code / Claude Desktop session_id),
--          alongside the per-developer user_email that already exists. This
--          front-loads the data for session-level reporting (epic #2753 WS-7)
--          so that layer is pure read-side aggregation.
--
-- Sibling of user_email (migration 059): both are asserted identity fields the
-- plugin/proxy forward as HTTP headers (X-User-Email / X-Session-Id) and the
-- write paths (agent check_policy → writeMCPDecisionAudit; orchestrator
-- auditToolCallHandler → LogToolCallAudit) persist here.
--
-- NULLABLE with no default: every existing writer that does not forward a
-- session id writes NULL, so existing behavior is byte-identical and the
-- column is purely additive. session_id is an ASSERTED attribution label, not
-- an authentication boundary.

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS session_id VARCHAR(255);

-- Partial index backing session-scoped reporting/filtering
-- (`WHERE session_id IS NOT NULL`): only rows that actually carry a session are
-- indexed, so the (majority) of non-session rows add no index weight.
CREATE INDEX IF NOT EXISTS idx_audit_logs_session_id
    ON audit_logs(session_id) WHERE session_id IS NOT NULL;

COMMENT ON COLUMN audit_logs.session_id IS 'AI-tool session id (Claude Code / Desktop) forwarded via X-Session-Id; asserted attribution label, not an auth boundary (#2753/#2754)';
