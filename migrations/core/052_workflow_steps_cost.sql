-- Add cost_usd column to workflow_steps for per-step cost tracking
ALTER TABLE workflow_steps ADD COLUMN IF NOT EXISTS cost_usd DOUBLE PRECISION;
