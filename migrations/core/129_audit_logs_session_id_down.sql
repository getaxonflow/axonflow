-- Migration 129 Down: Remove the session_id column from audit_logs
-- Rollback script for the canonical-row per-session identity field.

DROP INDEX IF EXISTS idx_audit_logs_session_id;

ALTER TABLE audit_logs
    DROP COLUMN IF EXISTS session_id;
