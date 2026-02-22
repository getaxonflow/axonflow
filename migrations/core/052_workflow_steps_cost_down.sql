-- Remove cost_usd column from workflow_steps
ALTER TABLE workflow_steps DROP COLUMN IF EXISTS cost_usd;
