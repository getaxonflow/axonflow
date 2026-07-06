-- Migration 140 Down: Remove the OTLP metric usage columns from usage_events
-- Rollback script for the /v1/metrics ingest usage-row shape.

DROP INDEX IF EXISTS idx_usage_events_metric_series;
DROP INDEX IF EXISTS idx_usage_events_session;
DROP INDEX IF EXISTS ux_usage_events_metric_point;

ALTER TABLE usage_events
    DROP COLUMN IF EXISTS session_id,
    DROP COLUMN IF EXISTS user_email,
    DROP COLUMN IF EXISTS metric_name,
    DROP COLUMN IF EXISTS metric_value,
    DROP COLUMN IF EXISTS metric_raw_value,
    DROP COLUMN IF EXISTS metric_temporality,
    DROP COLUMN IF EXISTS metric_series_key,
    DROP COLUMN IF EXISTS metric_attributes,
    DROP COLUMN IF EXISTS metric_time,
    DROP COLUMN IF EXISTS metric_start_time;
