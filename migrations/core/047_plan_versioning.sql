-- Migration 047: Plan versioning for MAP v1.0
-- Date: 2026-02-06
-- Purpose: Add version tracking and optimistic locking for plans
-- Note: updated_at is also set by the trigger from migration 037,
-- but we set it explicitly for clarity in version-update queries.

-- Add version column to plans table
ALTER TABLE plans ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1 NOT NULL;

-- Create plan_versions table for version history
CREATE TABLE IF NOT EXISTS plan_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id VARCHAR(255) NOT NULL REFERENCES plans(plan_id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    org_id TEXT,
    snapshot JSONB NOT NULL,
    changed_by VARCHAR(255),
    changed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    change_type VARCHAR(50) NOT NULL,
    change_summary TEXT,
    CONSTRAINT plan_versions_unique UNIQUE(plan_id, version)
);

-- Index for efficient version history lookups
CREATE INDEX IF NOT EXISTS idx_plan_versions_plan_id ON plan_versions(plan_id);
CREATE INDEX IF NOT EXISTS idx_plan_versions_changed_at ON plan_versions(changed_at);
CREATE INDEX IF NOT EXISTS idx_plan_versions_org_id ON plan_versions(org_id);
