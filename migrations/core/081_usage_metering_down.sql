-- Migration 081 rollback: drop usage metering tables + helper functions
--
-- WARNING: This drops the raw events + hourly/daily/monthly aggregates
-- and the cleanup_old_usage_events / aggregate_usage_hourly /
-- aggregate_usage_daily PL/pgSQL functions. The data is unrecoverable
-- once dropped — only run this rollback when the corresponding code
-- path (UsageRecorder enterprise build) has also been removed or
-- when starting from a fresh database.
--
-- Order: drop FK constraints first (silently — they may not exist on
-- legacy schemas), then functions, then aggregate tables, then the
-- root events table. Tables fall in reverse-creation order.

-- RLS policies on the dropped tables go away with the tables themselves,
-- so no explicit DROP POLICY needed before the DROP TABLE statements.

DROP FUNCTION IF EXISTS aggregate_usage_daily(DATE, DATE);
DROP FUNCTION IF EXISTS aggregate_usage_hourly(TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE);
DROP FUNCTION IF EXISTS cleanup_old_usage_events();

DROP TABLE IF EXISTS usage_monthly;
DROP TABLE IF EXISTS usage_daily;
DROP TABLE IF EXISTS usage_hourly;
DROP TABLE IF EXISTS usage_events;
