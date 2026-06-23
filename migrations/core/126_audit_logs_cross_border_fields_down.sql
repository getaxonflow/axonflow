-- Migration 126 Down: Remove Cross-Border Transfer Fields from audit_logs
-- Rollback script for the canonical-row cross-border transfer fields.

DROP INDEX IF EXISTS idx_audit_logs_transfer_basis;

ALTER TABLE audit_logs
    DROP COLUMN IF EXISTS transfer_basis,
    DROP COLUMN IF EXISTS data_residency;
