-- Copyright 2026 AxonFlow
-- SPDX-License-Identifier: BUSL-1.1
--
-- Migration: 041_workflows (DOWN)
-- Description: Rollback Workflow Control Plane tables

-- Drop trigger first
DROP TRIGGER IF EXISTS trigger_update_workflows_timestamp ON workflows;

-- Drop function
DROP FUNCTION IF EXISTS update_workflows_timestamp();

-- Drop indexes
DROP INDEX IF EXISTS idx_workflow_steps_pending;
DROP INDEX IF EXISTS idx_workflow_steps_decision;
DROP INDEX IF EXISTS idx_workflow_steps_workflow;
DROP INDEX IF EXISTS idx_workflows_source;
DROP INDEX IF EXISTS idx_workflows_created;
DROP INDEX IF EXISTS idx_workflows_org;
DROP INDEX IF EXISTS idx_workflows_tenant;
DROP INDEX IF EXISTS idx_workflows_status;

-- Drop tables (workflow_steps first due to FK)
DROP TABLE IF EXISTS workflow_steps;
DROP TABLE IF EXISTS workflows;

-- Log rollback
DO $$
BEGIN
    RAISE NOTICE 'Migration 041 (DOWN): Dropped workflows and workflow_steps tables';
END $$;
