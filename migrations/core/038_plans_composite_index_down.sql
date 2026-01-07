-- Copyright 2026 AxonFlow
-- SPDX-License-Identifier: BUSL-1.1
--
-- Migration: 038_plans_composite_index (DOWN)
-- Description: Remove composite index for cross-tenant plan queries

DROP INDEX IF EXISTS idx_plans_org_status;

DO $$
BEGIN
    RAISE NOTICE 'Migration 038 (DOWN): Removed composite index idx_plans_org_status';
END $$;
