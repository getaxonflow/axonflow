-- Migration 123 DOWN: drop the canonical-vocabulary CHECK constraint (#2638).
--
-- The up migration (1) normalized any residual non-canonical
-- audit_logs.policy_decision rows to the canonical set and (2) added the
-- audit_logs_policy_decision_check CHECK. The down path removes ONLY the CHECK,
-- restoring the pre-123 schema where policy_decision is an unconstrained
-- VARCHAR(50).
--
-- The data normalization is intentionally NOT reversed (forward-only, like
-- migration 122's down): the original legacy spellings are unrecoverable, and
-- the canonical set is the intended steady state for the column — every reader
-- already understands it. Dropping the schema constraint does not require
-- de-normalizing the data.
--
-- Idempotent: DROP CONSTRAINT IF EXISTS is a no-op if the constraint is absent.

BEGIN;

ALTER TABLE audit_logs
    DROP CONSTRAINT IF EXISTS audit_logs_policy_decision_check;

DO $$
BEGIN
    RAISE NOTICE 'Migration 123 DOWN: dropped audit_logs_policy_decision_check (data normalization is forward-only; see file header)';
END
$$;

COMMIT;
