-- Migration 055: Add trace_id column for external tracing correlation
-- Supports Langsmith, Datadog, OpenTelemetry trace ID propagation

ALTER TABLE workflows ADD COLUMN IF NOT EXISTS trace_id VARCHAR(255);

-- Partial index: only index workflows that have a trace_id set
CREATE INDEX IF NOT EXISTS idx_workflows_trace_id ON workflows (trace_id) WHERE trace_id IS NOT NULL;
