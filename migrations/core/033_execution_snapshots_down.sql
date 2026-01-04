-- Copyright 2025 AxonFlow
-- SPDX-License-Identifier: BUSL-1.1
--
-- Migration: 033_execution_snapshots (DOWN)
-- Description: Remove execution snapshots tables

-- Drop trigger and function
DROP TRIGGER IF EXISTS trigger_update_execution_summary_timestamp ON execution_summaries;
DROP FUNCTION IF EXISTS update_execution_summary_timestamp();

-- Drop indexes
DROP INDEX IF EXISTS idx_snapshots_request;
DROP INDEX IF EXISTS idx_snapshots_status;
DROP INDEX IF EXISTS idx_snapshots_created;
DROP INDEX IF EXISTS idx_summaries_org;
DROP INDEX IF EXISTS idx_summaries_tenant;
DROP INDEX IF EXISTS idx_summaries_status;
DROP INDEX IF EXISTS idx_summaries_created;
DROP INDEX IF EXISTS idx_summaries_workflow;

-- Drop tables
DROP TABLE IF EXISTS execution_snapshots;
DROP TABLE IF EXISTS execution_summaries;
