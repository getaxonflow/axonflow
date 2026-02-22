-- Migration 054 (down): Remove step_output column from workflow_steps

ALTER TABLE workflow_steps DROP COLUMN IF EXISTS step_output;
