-- Down-migration 141: drop the session-summary composite index (#2851/#2852).
-- Purely structural — no data changes to revert.

DROP INDEX IF EXISTS idx_audit_logs_tenant_ts_session;
