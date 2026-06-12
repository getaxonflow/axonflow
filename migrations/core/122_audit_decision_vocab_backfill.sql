-- Migration 122: one-time historical backfill normalizing the legacy Decision
-- Mode verdict vocabulary in audit_logs.policy_decision to the canonical set.
-- Date: 2026-06-11
-- Issue: #2643 (Audit-completeness E) / #2638 (vocabulary umbrella). See ADR-058.
-- Depends: 059_runtime_tables_to_migrations
--
-- WHY ----------------------------------------------------------------------
-- The /api/v1/decide writer (platform/agent/decision_handler.go) historically
-- persisted the WIRE verdict ('allow' / 'deny') straight into
-- audit_logs.policy_decision. That diverges from the canonical set the rest of
-- the audit subsystem uses — 'allowed' / 'blocked' / 'redacted' /
-- 'needs_approval' / 'error' — which the orchestrator response-plane writer
-- (#2630) emits and the audit summary handler buckets on. A legacy 'deny' row is
-- silently counted as "not blocked" by the summary handler's fallback, so a real
-- security block could read as 0-blocked / 100%-compliant.
--
-- Going forward the agent writer emits canonical values (decision_handler.go
-- canonicalAuditVerdict, #2643). This migration fixes the rows written BEFORE
-- that change so a query over policy_decision is uniform across all history.
--
-- SCOPE --------------------------------------------------------------------
-- Only the legacy tokens are touched: 'allow' -> 'allowed', and
-- 'deny' / 'denied' -> 'blocked' ('denied' is an alternate legacy spelling the
-- audit summary handler already buckets as blocked). 'needs_approval' is already
-- canonical and is left untouched. Idempotent: re-running is a no-op once no
-- legacy tokens remain (the WHERE clauses match nothing on a second pass).
--
-- NOTE: other planes' writers (MCP check_policy, gateway pre-check) may still
-- emit legacy tokens until buckets C/D land. This migration is the HISTORICAL
-- one-shot for the rows that exist today; the reader-side normalizer + any
-- periodic sweep are tracked under #2638 and are explicitly NOT part of this PR.
--
-- RLS POSTURE --------------------------------------------------------------
-- audit_logs is deliberately NOT FORCE-RLS (migration 101 deferred it for the
-- cross-org audit_cleanup worker). There is no WITH CHECK to satisfy, so this
-- UPDATE runs on the migration connection and succeeds identically under
-- AXONFLOW_DB_USE_APP_ROLE on or off.

BEGIN;

UPDATE audit_logs
   SET policy_decision = 'allowed'
 WHERE policy_decision = 'allow';

UPDATE audit_logs
   SET policy_decision = 'blocked'
 WHERE policy_decision IN ('deny', 'denied');

-- Verification — fail loudly if any legacy token survived the normalization
-- (Principle 3: a migration that silently no-ops on a partial failure is worse
-- than one that raises).
DO $$
DECLARE
    leftover BIGINT;
BEGIN
    SELECT count(*) INTO leftover
      FROM audit_logs
     WHERE policy_decision IN ('allow', 'deny', 'denied');
    IF leftover > 0 THEN
        RAISE EXCEPTION 'Migration 122 failed: % legacy allow/deny/denied rows remain in audit_logs.policy_decision', leftover;
    END IF;
    RAISE NOTICE 'Migration 122 verified: no legacy allow/deny/denied tokens remain in audit_logs.policy_decision';
END
$$;

COMMIT;
