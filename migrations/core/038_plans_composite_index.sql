-- Copyright 2026 AxonFlow
-- SPDX-License-Identifier: BUSL-1.1
--
-- Migration: 038_plans_composite_index
-- Description: Add composite index for cross-tenant plan queries
-- Related: PR #927 code review follow-up
--
-- This index optimizes queries that filter by org_id and status together,
-- which is the common pattern in GetPlanForExecution authorization checks.

CREATE INDEX IF NOT EXISTS idx_plans_org_status ON plans(org_id, status);

-- Log migration
DO $$
BEGIN
    RAISE NOTICE 'Migration 038: Added composite index idx_plans_org_status for cross-tenant queries';
END $$;
