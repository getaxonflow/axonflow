-- Migration 035 DOWN: Remove Sensitive Data Patterns
-- Date: 2026-01-05
-- Purpose: Rollback sensitive data detection patterns (Issue #891)

-- Remove sensitive data detection policies
DELETE FROM static_policies WHERE policy_id IN (
    'sys_sensitive_password',
    'sys_sensitive_api_key',
    'sys_sensitive_token',
    'sys_sensitive_secret',
    'sys_sensitive_credentials',
    'sys_sensitive_connection'
);
