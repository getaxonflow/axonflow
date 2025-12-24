-- Migration 031 Down: Remove System Policies
-- Purpose: Remove seeded system policies

-- Delete all system-tier static policies
DELETE FROM static_policies WHERE tier = 'system';

-- Delete all system-tier dynamic policies
DELETE FROM dynamic_policies WHERE tier = 'system';

-- Note: This will remove all system policies. Any customer overrides
-- in policy_overrides table will become orphaned but are kept for audit trail.
