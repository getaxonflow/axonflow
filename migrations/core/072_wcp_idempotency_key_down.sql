-- Down migration for 072_wcp_idempotency_key.sql

BEGIN;

DROP INDEX IF EXISTS idx_workflow_steps_idempotency_key;

ALTER TABLE workflow_steps
    DROP COLUMN IF EXISTS idempotency_key;

COMMIT;
