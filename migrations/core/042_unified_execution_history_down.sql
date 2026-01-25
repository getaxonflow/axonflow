-- Migration: 042_unified_execution_history_down.sql
-- Rollback for unified execution history

DROP VIEW IF EXISTS active_executions;
DROP FUNCTION IF EXISTS cleanup_old_execution_history(INTEGER);
DROP TRIGGER IF EXISTS trigger_execution_history_updated_at ON execution_history;
DROP FUNCTION IF EXISTS update_execution_history_updated_at();
DROP TABLE IF EXISTS execution_history;
