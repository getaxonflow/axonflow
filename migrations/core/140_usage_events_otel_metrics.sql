-- Migration 140: OTLP metric usage rows on the canonical usage_events store
-- Date: 2026-07-05
-- Purpose: Land Claude Code's native OTLP *metrics* export (token / cost /
--          session / lines-of-code / tool-decision counters, POST /v1/metrics)
--          as canonical usage rows in the SAME usage_events table every other
--          metering plane writes to — not a parallel/satellite store. The
--          existing columns are shaped for one API/LLM call each; an OTLP
--          metric datapoint is a named counter increment keyed on
--          session_id / user_email, so it needs its own descriptive columns.
--
-- Rows written by the metrics ingest use event_type = 'claude_code_metric'.
-- Because the usage rollups (usage_hourly / usage_daily, migration 081) group
-- BY event_type, these rows aggregate into their own buckets and never blend
-- into 'api_call' / 'llm_request' counts. Token deltas are ALSO mirrored into
-- the existing prompt_tokens / completion_tokens / total_tokens columns (and
-- cost into estimated_cost_cents) so the existing token/cost aggregates carry
-- Claude Code usage with no rollup change.
--
-- metric_value is the NORMALIZED DELTA for the datapoint (cumulative OTLP
-- streams are converted to deltas at ingest using metric_series_key +
-- metric_raw_value + metric_start_time; see platform/common/usage). Summing
-- metric_value per metric_name is therefore always correct, regardless of the
-- exporter's aggregation temporality.
--
-- All columns are NULLABLE with no default: every existing writer is untouched
-- and the migration is purely additive. session_id / user_email are ASSERTED
-- attribution labels from the telemetry, not an authentication boundary — the
-- org_id scope on every row still comes from the authenticated license.

ALTER TABLE usage_events
    ADD COLUMN IF NOT EXISTS session_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS user_email VARCHAR(320),
    ADD COLUMN IF NOT EXISTS metric_name VARCHAR(128),
    ADD COLUMN IF NOT EXISTS metric_value DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS metric_raw_value DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS metric_temporality VARCHAR(16),
    ADD COLUMN IF NOT EXISTS metric_series_key VARCHAR(64),
    ADD COLUMN IF NOT EXISTS metric_attributes JSONB,
    ADD COLUMN IF NOT EXISTS metric_time TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS metric_start_time TIMESTAMP WITH TIME ZONE;

-- OPERATIONAL NOTE: the three CREATE INDEX below are plain (non-CONCURRENT —
-- the migration runner is transactional) and take a SHARE lock on usage_events
-- for the build scan, briefly blocking concurrent usage writes on deployments
-- with a large usage_events table. All three are PARTIAL on metric columns
-- that are NULL for every pre-existing row, so the scan is the only cost —
-- no rewrite. Schedule the upgrade like any other migration window.

-- Cumulative→delta normalization reads the latest prior datapoint of the same
-- series (org-scoped under RLS). Partial: only metric rows carry a series key,
-- so api_call / llm_request rows add no index weight.
CREATE INDEX IF NOT EXISTS idx_usage_events_metric_series
    ON usage_events(metric_series_key, id DESC)
    WHERE metric_series_key IS NOT NULL;

-- Exact-duplicate datapoint dedup: an OTLP series emits at most one datapoint
-- per timestamp, so a second row with the same (series, time) is a client
-- RETRY of an export the server already committed (the client saw a timeout).
-- The ingest INSERTs with ON CONFLICT DO NOTHING against this index, so the
-- retry lands zero rows instead of double-counting usage.
CREATE UNIQUE INDEX IF NOT EXISTS ux_usage_events_metric_point
    ON usage_events(metric_series_key, metric_time)
    WHERE metric_series_key IS NOT NULL AND metric_time IS NOT NULL;

-- Session/user-keyed usage reporting ("what did this Claude Code session /
-- developer consume") — the read this plane exists to serve.
CREATE INDEX IF NOT EXISTS idx_usage_events_session
    ON usage_events(session_id, created_at DESC)
    WHERE session_id IS NOT NULL;

COMMENT ON COLUMN usage_events.session_id IS 'AI-tool session id (OTLP session.id attribute); asserted attribution label, not an auth boundary (#2832)';
COMMENT ON COLUMN usage_events.user_email IS 'Developer email (OTLP user.email attribute); asserted attribution label, not an auth boundary (#2832)';
COMMENT ON COLUMN usage_events.metric_name IS 'OTLP metric name, e.g. claude_code.token.usage (#2832)';
COMMENT ON COLUMN usage_events.metric_value IS 'Normalized DELTA value for this datapoint — always safe to SUM per metric_name (#2832)';
COMMENT ON COLUMN usage_events.metric_raw_value IS 'Datapoint value exactly as exported (delta or cumulative per metric_temporality) (#2832)';
COMMENT ON COLUMN usage_events.metric_temporality IS 'OTLP aggregation temporality of the source stream: delta | cumulative (#2832)';
COMMENT ON COLUMN usage_events.metric_series_key IS 'SHA-256 over org + metric name + full attribute set; identifies one OTLP series for cumulative→delta normalization (#2832)';
COMMENT ON COLUMN usage_events.metric_attributes IS 'Allowlisted OTLP datapoint/resource attributes (structural identifiers only; unknown keys are dropped at ingest, never stored) (#2832)';
COMMENT ON COLUMN usage_events.metric_time IS 'Datapoint TimeUnixNano (event time); created_at stays ingest time for rollup semantics (#2832)';
COMMENT ON COLUMN usage_events.metric_start_time IS 'Datapoint StartTimeUnixNano; a changed start time marks a counter reset for delta normalization (#2832)';
