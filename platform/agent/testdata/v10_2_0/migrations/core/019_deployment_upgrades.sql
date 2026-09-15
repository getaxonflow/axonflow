-- Migration 019: Deployment Upgrades Table
-- Tracks application upgrade history for customer deployments
-- Part of ADR-006: Decoupled Deployments

-- Add deployment configuration fields to organizations
ALTER TABLE organizations
ADD COLUMN IF NOT EXISTS deployment_cluster VARCHAR(255),
ADD COLUMN IF NOT EXISTS deployment_stack VARCHAR(255),
ADD COLUMN IF NOT EXISTS deployment_region VARCHAR(50) DEFAULT 'eu-central-1';

COMMENT ON COLUMN organizations.deployment_cluster IS 'ECS cluster name for this organization';
COMMENT ON COLUMN organizations.deployment_stack IS 'CloudFormation stack name for this organization';
COMMENT ON COLUMN organizations.deployment_region IS 'AWS region where the deployment is hosted';

-- Create deployment_upgrades table to track upgrade history
CREATE TABLE IF NOT EXISTS deployment_upgrades (
    id SERIAL PRIMARY KEY,
    upgrade_id VARCHAR(100) UNIQUE NOT NULL,
    org_id VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    services TEXT NOT NULL,
    version VARCHAR(100),
    initiated_by VARCHAR(255),
    success_count INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_deployment_org
        FOREIGN KEY (org_id)
        REFERENCES organizations(org_id)
        ON DELETE CASCADE
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_deployment_upgrades_org_id ON deployment_upgrades(org_id);
CREATE INDEX IF NOT EXISTS idx_deployment_upgrades_status ON deployment_upgrades(status);
CREATE INDEX IF NOT EXISTS idx_deployment_upgrades_started_at ON deployment_upgrades(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_deployment_upgrades_org_started ON deployment_upgrades(org_id, started_at DESC);

COMMENT ON TABLE deployment_upgrades IS 'Tracks application upgrade history for customer deployments';
COMMENT ON COLUMN deployment_upgrades.upgrade_id IS 'Unique identifier for the upgrade operation';
COMMENT ON COLUMN deployment_upgrades.status IS 'Status: PENDING, IN_PROGRESS, SUCCESS, FAILED, PARTIAL';
COMMENT ON COLUMN deployment_upgrades.services IS 'Comma-separated list of services being upgraded';
COMMENT ON COLUMN deployment_upgrades.version IS 'Target version/tag being deployed';
COMMENT ON COLUMN deployment_upgrades.initiated_by IS 'Email of user who initiated the upgrade';
COMMENT ON COLUMN deployment_upgrades.success_count IS 'Number of services successfully upgraded';
COMMENT ON COLUMN deployment_upgrades.failed_count IS 'Number of services that failed to upgrade';
COMMENT ON COLUMN deployment_upgrades.metadata IS 'Additional metadata (deployment IDs, task definitions, etc.)';

-- Enable RLS on deployment_upgrades (if RLS is enabled on the database)
DO $$
BEGIN
    -- Check if RLS is enabled on organizations table
    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
        AND c.relname = 'organizations'
        AND c.relrowsecurity = true
    ) THEN
        -- Enable RLS on deployment_upgrades
        ALTER TABLE deployment_upgrades ENABLE ROW LEVEL SECURITY;

        -- Create policy for organization isolation
        DROP POLICY IF EXISTS deployment_upgrades_org_isolation ON deployment_upgrades;
        CREATE POLICY deployment_upgrades_org_isolation ON deployment_upgrades
            USING (org_id = current_setting('app.current_org_id', true))
            WITH CHECK (org_id = current_setting('app.current_org_id', true));

        RAISE NOTICE 'RLS enabled on deployment_upgrades table';
    END IF;
END
$$;
