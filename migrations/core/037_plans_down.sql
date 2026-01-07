-- Copyright 2025 AxonFlow
-- SPDX-License-Identifier: BUSL-1.1
--
-- Migration: 037_plans (DOWN)
-- Description: Remove plans table

DROP TRIGGER IF EXISTS trigger_update_plans_timestamp ON plans;
DROP FUNCTION IF EXISTS update_plans_timestamp();
DROP FUNCTION IF EXISTS cleanup_expired_plans();
DROP TABLE IF EXISTS plans;

DO $$
BEGIN
    RAISE NOTICE 'Migration 037 (DOWN): Removed plans table';
END $$;
