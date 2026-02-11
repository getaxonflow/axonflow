-- Migration: 049_execution_history_drop_tenant_fk.sql
-- Description: Remove FK constraint on execution_history.tenant_id
-- Fixes: Community mode execution tracking fails when tenant_id (from SDK ClientID)
--        doesn't exist in organizations table. The RLS policy handles tenant isolation
--        independently via app.current_tenant_id session variable.

ALTER TABLE execution_history
    DROP CONSTRAINT IF EXISTS execution_history_tenant_id_fkey;
