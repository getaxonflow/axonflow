-- Migration 029 Down: Remove source column from role_assignments

DROP INDEX IF EXISTS idx_role_assignments_source;
ALTER TABLE role_assignments DROP COLUMN IF EXISTS source;
