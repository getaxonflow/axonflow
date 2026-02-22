-- Rollback: remove per-step token tracking from workflow_steps
ALTER TABLE workflow_steps DROP COLUMN IF EXISTS tokens_in;
ALTER TABLE workflow_steps DROP COLUMN IF EXISTS tokens_out;
