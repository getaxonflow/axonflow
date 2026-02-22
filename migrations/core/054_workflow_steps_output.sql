-- Migration 054: Add step_output column to workflow_steps
-- Stores post-execution output data sent by SDKs at step completion time.
-- tokens_in, tokens_out, cost_usd columns already exist (migrations 051/052);
-- they are updated via COALESCE at completion time rather than added here.

ALTER TABLE workflow_steps ADD COLUMN IF NOT EXISTS step_output JSONB;
