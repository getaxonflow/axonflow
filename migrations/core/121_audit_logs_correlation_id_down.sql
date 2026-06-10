-- Migration 121 DOWN: remove the audit_logs correlation_id column + its partial
-- index (#2598 / ADR-058 Phase 1.5).
--
-- Reversible: correlation_id is dual-written into policy_details JSONB
-- (policy_details->>'correlation_id'), which the up migration leaves intact, so
-- dropping the column loses no data the JSONB doesn't still carry. Safe to
-- re-run.

BEGIN;

DROP INDEX IF EXISTS idx_audit_logs_correlation_id;

ALTER TABLE audit_logs DROP COLUMN IF EXISTS correlation_id;

COMMIT;
