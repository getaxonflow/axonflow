-- Down migration for 071_wcp_retry_context_counters.sql

BEGIN;

ALTER TABLE workflow_steps
    DROP COLUMN IF EXISTS first_attempt_at,
    DROP COLUMN IF EXISTS last_decision,
    DROP COLUMN IF EXISTS completion_count,
    DROP COLUMN IF EXISTS gate_count;

COMMIT;
