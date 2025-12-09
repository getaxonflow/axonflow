-- Migration 022: Policy Versioning and Audit Trail
-- Adds version tracking to dynamic_policies and creates version history table
-- Part of Track B: Policy Management Database Schema

-- Add version columns to existing policies table
ALTER TABLE dynamic_policies
    ADD COLUMN IF NOT EXISTS version INT DEFAULT 1,
    ADD COLUMN IF NOT EXISTS created_by VARCHAR(255),
    ADD COLUMN IF NOT EXISTS updated_by VARCHAR(255);

-- Create index for version queries
CREATE INDEX IF NOT EXISTS idx_dynamic_policies_version ON dynamic_policies(id, version);

-- Policy version history table
CREATE TABLE IF NOT EXISTS policy_versions (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    policy_id VARCHAR(255) NOT NULL,
    version INT NOT NULL,
    snapshot JSONB NOT NULL,
    changed_by VARCHAR(255),
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    change_type VARCHAR(50) NOT NULL, -- create, update, enable, disable, delete
    change_summary TEXT,

    CONSTRAINT fk_policy_versions_policy
        FOREIGN KEY (policy_id)
        REFERENCES dynamic_policies(policy_id)
        ON DELETE CASCADE
);

-- Indexes for version queries
CREATE INDEX IF NOT EXISTS idx_policy_versions_policy_id ON policy_versions(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_versions_changed_at ON policy_versions(changed_at);
CREATE INDEX IF NOT EXISTS idx_policy_versions_change_type ON policy_versions(change_type);

-- Compound index for common query pattern
CREATE INDEX IF NOT EXISTS idx_policy_versions_policy_version
    ON policy_versions(policy_id, version DESC);

-- Add RLS policy for multi-tenant isolation
ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;

CREATE POLICY policy_versions_tenant_isolation ON policy_versions
    USING (
        policy_id IN (
            SELECT policy_id FROM dynamic_policies
            WHERE tenant_id = current_setting('app.tenant_id', true)
        )
    );

-- Comment for documentation
COMMENT ON TABLE policy_versions IS 'Stores version history snapshots for policy audit trail';
COMMENT ON COLUMN policy_versions.snapshot IS 'Complete policy state at this version (JSONB)';
COMMENT ON COLUMN policy_versions.change_type IS 'Type of change: create, update, enable, disable, delete';
