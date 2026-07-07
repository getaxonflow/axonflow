-- Migration 141: composite index for session-summary bucket scans
-- Date: 2026-07-07
-- Issue: #2851 (folded into #2852, session-summary Part 2). Part 1: #2759.
--
-- GET /api/v1/audit/session-summary aggregates audit_logs three times over
-- the same predicate shape: tenant_id = $1 AND timestamp >= $2 AND
-- timestamp < $3, grouped on a session_id-keyed bucket expression. The
-- existing single-column indexes (tenant_id; timestamp; session_id partial,
-- core/129) each cover one leg; this composite lets one range scan serve the
-- whole WHERE and feed the GROUP BY without a re-sort on large tenants.
--
-- Plain CREATE INDEX (non-CONCURRENT — the migration runner is
-- transactional): takes a SHARE lock on audit_logs for the build scan,
-- briefly blocking concurrent audit writes on deployments with a large
-- table, same operational note as migration 140's usage_events indexes.
-- Idempotent via IF NOT EXISTS.

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_ts_session
    ON audit_logs(tenant_id, timestamp, session_id);
