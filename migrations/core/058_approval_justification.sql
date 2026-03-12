-- Add justification column for HITL approval audit trail
ALTER TABLE workflow_steps ADD COLUMN IF NOT EXISTS approval_comment TEXT;
