-- Add per-step token tracking to workflow_steps
ALTER TABLE workflow_steps ADD COLUMN IF NOT EXISTS tokens_in INTEGER;
ALTER TABLE workflow_steps ADD COLUMN IF NOT EXISTS tokens_out INTEGER;
