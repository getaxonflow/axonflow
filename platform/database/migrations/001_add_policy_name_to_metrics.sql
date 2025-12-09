-- Migration: Add policy_name column to policy_metrics table
-- Date: 2025-10-20
-- Issue: Code expects policy_name column but schema only has policy_id

-- Add the missing column
ALTER TABLE policy_metrics
ADD COLUMN IF NOT EXISTS policy_name VARCHAR(255);

-- Add columns expected by orchestrator code
ALTER TABLE policy_metrics
ADD COLUMN IF NOT EXISTS execution_time_ms INTEGER;

ALTER TABLE policy_metrics
ADD COLUMN IF NOT EXISTS success BOOLEAN;

ALTER TABLE policy_metrics
ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(100);

-- Add timestamp column if not exists (for backward compatibility)
ALTER TABLE policy_metrics
ADD COLUMN IF NOT EXISTS timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Create index for new columns
CREATE INDEX IF NOT EXISTS idx_policy_metrics_name ON policy_metrics(policy_name);
CREATE INDEX IF NOT EXISTS idx_policy_metrics_tenant ON policy_metrics(tenant_id);
