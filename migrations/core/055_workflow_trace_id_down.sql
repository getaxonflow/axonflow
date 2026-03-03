DROP INDEX IF EXISTS idx_workflows_trace_id;
ALTER TABLE workflows DROP COLUMN IF EXISTS trace_id;
