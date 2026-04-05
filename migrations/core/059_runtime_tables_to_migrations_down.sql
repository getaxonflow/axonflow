-- Migration 059 DOWN: Remove tables introduced by this migration
-- Only drops audit_logs and media_governance_config — these are the tables
-- that 059 actually introduces. dynamic_policies and policy_metrics belong
-- to migration 010 and are NOT touched here.
--
-- WARNING: This drops all data in these tables. Only use in development.

-- Drop audit_logs indexes first
DROP INDEX IF EXISTS idx_audit_logs_timestamp;
DROP INDEX IF EXISTS idx_audit_logs_user_email;
DROP INDEX IF EXISTS idx_audit_logs_tenant_id;
DROP INDEX IF EXISTS idx_audit_logs_request_id;
DROP INDEX IF EXISTS idx_audit_logs_policy_decision;
DROP INDEX IF EXISTS idx_audit_logs_org_id;

-- Drop tables
DROP TABLE IF EXISTS media_governance_config;
DROP TABLE IF EXISTS audit_logs;
