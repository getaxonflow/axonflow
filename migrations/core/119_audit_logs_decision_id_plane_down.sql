-- Migration 119 DOWN: remove the audit_logs decision_id / plane / obligations
-- columns + the partial decision_id index (#2592 / ADR-058 Phase 1).
--
-- Reversible: the column values are a backfilled copy of policy_details JSONB
-- (which is left intact by the up migration), so dropping the columns loses no
-- data the JSONB doesn't still carry. Safe to re-run.

BEGIN;

DROP INDEX IF EXISTS idx_audit_logs_decision_id;

ALTER TABLE audit_logs DROP COLUMN IF EXISTS obligations;
ALTER TABLE audit_logs DROP COLUMN IF EXISTS plane;
ALTER TABLE audit_logs DROP COLUMN IF EXISTS decision_id;

COMMIT;
