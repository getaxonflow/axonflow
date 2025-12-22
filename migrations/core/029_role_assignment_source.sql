-- Migration 029: Add source column to role_assignments
-- Tracks how a role was assigned (manual, scim, api, etc.)
-- This enables SCIM sync to only remove roles it assigned, not manually assigned roles

-- Add source column with default 'manual' for existing assignments
ALTER TABLE role_assignments
ADD COLUMN IF NOT EXISTS source VARCHAR(50) DEFAULT 'manual';

-- Update existing SCIM-assigned roles (identified by assigned_by = 'scim-sync')
UPDATE role_assignments
SET source = 'scim'
WHERE assigned_by = 'scim-sync' OR assigned_by LIKE 'scim%';

-- Add index for filtering by source
CREATE INDEX IF NOT EXISTS idx_role_assignments_source ON role_assignments(source);

-- Comments
COMMENT ON COLUMN role_assignments.source IS 'How the role was assigned: manual, scim, api, etc.';
