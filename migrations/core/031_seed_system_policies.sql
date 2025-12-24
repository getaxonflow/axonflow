-- Migration 031: Seed System Policies
-- Date: 2025-12-24
-- Purpose: Seed all 63 system policies (53 static + 10 dynamic) with proper categories
-- Related: ADR-020 - Unified Policy Architecture, Issue #724

-- =============================================================================
-- PHASE 1: Static System Policies (53 total)
-- =============================================================================

-- First, update any existing policies to be non-system (they'll be replaced)
UPDATE static_policies SET tier = 'tenant' WHERE tier = 'system' OR tier IS NULL;

-- =============================================================================
-- Security - SQL Injection Patterns (37 patterns)
-- Category: security-sqli
-- =============================================================================

INSERT INTO static_policies (
    policy_id, name, category, tier, pattern, severity, description, action, priority, enabled, tenant_id, created_by
) VALUES
-- UNION-based SQL injection (2 patterns)
('sys_sqli_union_select', 'UNION SELECT Detection', 'security-sqli', 'system',
 '(?i)\bUNION\s+(ALL\s+)?SELECT\b', 'critical',
 'Detects UNION SELECT statements used to extract data', 'block', 100, true, 'global', 'system'),
('sys_sqli_union_injection', 'UNION Injection After Termination', 'security-sqli', 'system',
 '(?i)[''"\)]\s*UNION\s+(ALL\s+)?SELECT', 'critical',
 'Detects UNION injection after string termination', 'block', 100, true, 'global', 'system'),

-- Boolean-based blind SQL injection (3 patterns)
('sys_sqli_or_true', 'OR True Condition', 'security-sqli', 'system',
 '(?i)\bOR\s+[''"]?\d+[''"]?\s*=\s*[''"]?\d+[''"]?', 'high',
 'Detects OR with always-true numeric comparison (OR 1=1)', 'block', 90, true, 'global', 'system'),
('sys_sqli_or_string', 'OR String Condition', 'security-sqli', 'system',
 '(?i)\bOR\s+[''"][^''"]*[''"]\s*=\s*[''"][^''"]*[''"]\s*', 'high',
 'Detects OR with always-true string comparison (OR ''a''=''a'')', 'block', 90, true, 'global', 'system'),
('sys_sqli_and_false', 'AND False Condition', 'security-sqli', 'system',
 '(?i)\bAND\s+[''"]?\d+[''"]?\s*=\s*[''"]?\d+[''"]?', 'high',
 'Detects AND with numeric comparison for boolean blind', 'block', 90, true, 'global', 'system'),

-- Time-based blind SQL injection (4 patterns)
('sys_sqli_sleep', 'MySQL SLEEP Function', 'security-sqli', 'system',
 '(?i)\bSLEEP\s*\(\s*\d+\s*\)', 'critical',
 'Detects MySQL SLEEP function for time-based blind injection', 'block', 100, true, 'global', 'system'),
('sys_sqli_waitfor', 'SQL Server WAITFOR DELAY', 'security-sqli', 'system',
 '(?i)\bWAITFOR\s+DELAY\s+[''"][^''"]+[''"]\s*', 'critical',
 'Detects SQL Server WAITFOR DELAY for time-based blind injection', 'block', 100, true, 'global', 'system'),
('sys_sqli_pg_sleep', 'PostgreSQL pg_sleep', 'security-sqli', 'system',
 '(?i)\bPG_SLEEP\s*\(\s*\d+\s*\)', 'critical',
 'Detects PostgreSQL pg_sleep function', 'block', 100, true, 'global', 'system'),
('sys_sqli_benchmark', 'MySQL BENCHMARK Function', 'security-sqli', 'system',
 '(?i)\bBENCHMARK\s*\(\s*\d+\s*,', 'critical',
 'Detects MySQL BENCHMARK function for time-based injection', 'block', 100, true, 'global', 'system'),

-- Error-based SQL injection (3 patterns)
('sys_sqli_extractvalue', 'EXTRACTVALUE Function', 'security-sqli', 'system',
 '(?i)\bEXTRACTVALUE\s*\(', 'high',
 'Detects EXTRACTVALUE function used in error-based injection', 'block', 90, true, 'global', 'system'),
('sys_sqli_updatexml', 'UPDATEXML Function', 'security-sqli', 'system',
 '(?i)\bUPDATEXML\s*\(', 'high',
 'Detects UPDATEXML function used in error-based injection', 'block', 90, true, 'global', 'system'),
('sys_sqli_convert_int', 'CONVERT INT Injection', 'security-sqli', 'system',
 '(?i)\bCONVERT\s*\(\s*INT\s*,', 'high',
 'Detects CONVERT(INT, ...) for error-based injection', 'block', 90, true, 'global', 'system'),

-- Stacked queries (5 patterns)
('sys_sqli_stacked_drop', 'Stacked DROP Statement', 'security-sqli', 'system',
 '(?i);\s*DROP\s+(TABLE|DATABASE)\b', 'critical',
 'Detects stacked DROP TABLE/DATABASE statement', 'block', 100, true, 'global', 'system'),
('sys_sqli_stacked_delete', 'Stacked DELETE Statement', 'security-sqli', 'system',
 '(?i);\s*DELETE\s+FROM\b', 'critical',
 'Detects stacked DELETE statement', 'block', 100, true, 'global', 'system'),
('sys_sqli_stacked_update', 'Stacked UPDATE Statement', 'security-sqli', 'system',
 '(?i);\s*UPDATE\s+\w+\s+SET\b', 'critical',
 'Detects stacked UPDATE statement', 'block', 100, true, 'global', 'system'),
('sys_sqli_stacked_insert', 'Stacked INSERT Statement', 'security-sqli', 'system',
 '(?i);\s*INSERT\s+INTO\b', 'critical',
 'Detects stacked INSERT statement', 'block', 100, true, 'global', 'system'),
('sys_sqli_stacked_exec', 'Stacked EXEC Statement', 'security-sqli', 'system',
 '(?i);\s*(EXEC|EXECUTE)\s*\(', 'critical',
 'Detects stacked EXEC/EXECUTE statement', 'block', 100, true, 'global', 'system'),

-- Comment-based injection (3 patterns)
('sys_sqli_inline_comment', 'Inline Comment Injection', 'security-sqli', 'system',
 '(?i)/\*.*\*/\s*(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)', 'high',
 'Detects SQL commands after inline comment', 'block', 90, true, 'global', 'system'),
('sys_sqli_line_comment_mysql', 'MySQL Line Comment Injection', 'security-sqli', 'system',
 '(?i)#\s*(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)', 'high',
 'Detects SQL commands after MySQL line comment', 'block', 90, true, 'global', 'system'),
('sys_sqli_line_comment_dash', 'Double-Dash Comment Injection', 'security-sqli', 'system',
 '(?i)--\s*(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)', 'high',
 'Detects SQL commands after double-dash comment', 'block', 90, true, 'global', 'system'),

-- Generic patterns (9 patterns)
('sys_sqli_select_from', 'SELECT FROM After Termination', 'security-sqli', 'system',
 '(?i)[''"\)]\s*;\s*SELECT\s+.+\s+FROM\b', 'critical',
 'Detects SELECT ... FROM after string termination', 'block', 100, true, 'global', 'system'),
('sys_sqli_admin_bypass', 'Authentication Bypass', 'security-sqli', 'system',
 '(?i)[''"]?\s*OR\s+[''"]?[^''"]*[''"]?\s*=\s*[''"]?[^''"]*[''"]?\s*--', 'critical',
 'Detects authentication bypass pattern with comment', 'block', 100, true, 'global', 'system'),
('sys_sqli_hex_encoding', 'Hex-Encoded Payload', 'security-sqli', 'system',
 '(?i)0x[0-9a-f]{8,}', 'medium',
 'Detects potential hex-encoded SQL injection payload', 'block', 70, true, 'global', 'system'),
('sys_sqli_char_function', 'CHAR Function Obfuscation', 'security-sqli', 'system',
 '(?i)\bCHAR\s*\(\s*\d+(\s*,\s*\d+)+\s*\)', 'high',
 'Detects CHAR() function used to obfuscate injection', 'block', 90, true, 'global', 'system'),
('sys_sqli_concat_select', 'CONCAT with Embedded SELECT', 'security-sqli', 'system',
 '(?i)\bCONCAT\s*\([^)]*SELECT\b', 'high',
 'Detects CONCAT with embedded SELECT', 'block', 90, true, 'global', 'system'),
('sys_sqli_information_schema', 'INFORMATION_SCHEMA Access', 'security-sqli', 'system',
 '(?i)\bINFORMATION_SCHEMA\b', 'high',
 'Detects access to INFORMATION_SCHEMA for database enumeration', 'block', 90, true, 'global', 'system'),
('sys_sqli_sys_tables', 'System Tables Access', 'security-sqli', 'system',
 '(?i)\b(sysobjects|syscolumns|sys\.tables|sys\.columns)\b', 'high',
 'Detects access to system tables for database enumeration', 'block', 90, true, 'global', 'system'),
('sys_sqli_load_file', 'LOAD_FILE Function', 'security-sqli', 'system',
 '(?i)\bLOAD_FILE\s*\(', 'critical',
 'Detects LOAD_FILE function for file access', 'block', 100, true, 'global', 'system'),
('sys_sqli_into_outfile', 'INTO OUTFILE/DUMPFILE', 'security-sqli', 'system',
 '(?i)\bINTO\s+(OUT|DUMP)FILE\b', 'critical',
 'Detects INTO OUTFILE/DUMPFILE for file writing', 'block', 100, true, 'global', 'system'),

-- Dangerous query patterns (8 patterns)
('sys_sqli_drop_table', 'DROP TABLE Statement', 'security-sqli', 'system',
 '(?i)\bDROP\s+TABLE\b', 'critical',
 'Detects DROP TABLE statement', 'block', 100, true, 'global', 'system'),
('sys_sqli_drop_database', 'DROP DATABASE Statement', 'security-sqli', 'system',
 '(?i)\bDROP\s+DATABASE\b', 'critical',
 'Detects DROP DATABASE statement', 'block', 100, true, 'global', 'system'),
('sys_sqli_truncate', 'TRUNCATE TABLE Statement', 'security-sqli', 'system',
 '(?i)\bTRUNCATE\s+TABLE\b', 'critical',
 'Detects TRUNCATE TABLE statement', 'block', 100, true, 'global', 'system'),
('sys_sqli_alter_table', 'ALTER TABLE Statement', 'security-sqli', 'system',
 '(?i)\bALTER\s+TABLE\b', 'high',
 'Detects ALTER TABLE statement (schema modification)', 'block', 90, true, 'global', 'system'),
('sys_sqli_delete_no_where', 'DELETE Without WHERE', 'security-sqli', 'system',
 '(?i)\bDELETE\s+FROM\s+\w+\s*(?:;|$)', 'critical',
 'Detects DELETE FROM without WHERE clause', 'block', 100, true, 'global', 'system'),
('sys_sqli_create_user', 'CREATE USER Statement', 'security-sqli', 'system',
 '(?i)\bCREATE\s+USER\b', 'critical',
 'Detects CREATE USER statement', 'block', 100, true, 'global', 'system'),
('sys_sqli_grant', 'GRANT Privileges Statement', 'security-sqli', 'system',
 '(?i)\bGRANT\s+', 'critical',
 'Detects GRANT privilege statement', 'block', 100, true, 'global', 'system'),
('sys_sqli_revoke', 'REVOKE Privileges Statement', 'security-sqli', 'system',
 '(?i)\bREVOKE\s+', 'critical',
 'Detects REVOKE privilege statement', 'block', 100, true, 'global', 'system')

ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    tier = EXCLUDED.tier,
    pattern = EXCLUDED.pattern,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    action = EXCLUDED.action,
    priority = EXCLUDED.priority,
    enabled = EXCLUDED.enabled,
    created_by = EXCLUDED.created_by,
    updated_at = NOW();

-- =============================================================================
-- Security - Admin Access Patterns (4 patterns)
-- Category: security-admin
-- =============================================================================

INSERT INTO static_policies (
    policy_id, name, category, tier, pattern, severity, description, action, priority, enabled, tenant_id, created_by
) VALUES
('sys_admin_users_table', 'Users Table Access', 'security-admin', 'system',
 '\busers\b', 'high',
 'Access to users table requires admin privileges', 'block', 80, true, 'global', 'system'),
('sys_admin_audit_log', 'Audit Log Access', 'security-admin', 'system',
 'audit_log', 'high',
 'Access to audit logs requires admin privileges', 'block', 80, true, 'global', 'system'),
('sys_admin_config_table', 'Configuration Table Access', 'security-admin', 'system',
 'config_|admin_|system_', 'high',
 'Access to system configuration requires admin privileges', 'block', 80, true, 'global', 'system'),
('sys_admin_info_schema', 'Information Schema Access', 'security-admin', 'system',
 'information_schema|pg_catalog|mysql\.user', 'medium',
 'System schema access requires admin privileges', 'block', 70, true, 'global', 'system')

ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    tier = EXCLUDED.tier,
    pattern = EXCLUDED.pattern,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    action = EXCLUDED.action,
    priority = EXCLUDED.priority,
    enabled = EXCLUDED.enabled,
    created_by = EXCLUDED.created_by,
    updated_at = NOW();

-- =============================================================================
-- PII Detection - Global Patterns (7 patterns)
-- Category: pii-global
-- =============================================================================

INSERT INTO static_policies (
    policy_id, name, category, tier, pattern, severity, description, action, priority, enabled, tenant_id, created_by
) VALUES
('sys_pii_credit_card', 'Credit Card Number Detection', 'pii-global', 'system',
 '\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|2[2-7]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12}|3(?:0[0-5]|[68]\d)\d{11}|(?:2131|1800|35\d{3})\d{11})\b|\b(?:\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}|3[47]\d{2}[- ]\d{4}[- ]\d{4}[- ]\d{3}|3(?:0[0-5]|[68]\d)\d[- ]\d{4}[- ]\d{4}[- ]\d{2})\b', 'critical',
 'Credit card numbers detected - automatic redaction required for PCI compliance', 'block', 100, true, 'global', 'system'),
('sys_pii_email', 'Email Address Detection', 'pii-global', 'system',
 '\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b', 'medium',
 'Email address detected - may require redaction under GDPR', 'log', 50, true, 'global', 'system'),
('sys_pii_phone', 'Phone Number Detection', 'pii-global', 'system',
 '(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}\b|\+[0-9]{1,3}[-.\s]?[0-9]{6,14}\b', 'medium',
 'Phone number detected - may require redaction for privacy', 'log', 50, true, 'global', 'system'),
('sys_pii_ip_address', 'IP Address Detection', 'pii-global', 'system',
 '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', 'medium',
 'IP address detected - may identify user location', 'log', 50, true, 'global', 'system'),
('sys_pii_passport', 'Passport Number Detection', 'pii-global', 'system',
 '\b[A-Z]{1,2}[0-9]{6,9}\b', 'high',
 'Passport numbers detected in query - automatic redaction required', 'block', 80, true, 'global', 'system'),
('sys_pii_dob', 'Date of Birth Detection', 'pii-global', 'system',
 '\b(?:(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12][0-9]|3[01])[/\-](?:19|20)\d{2}|(?:19|20)\d{2}[/\-](?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12][0-9]|3[01]))\b', 'high',
 'Date detected - may be date of birth requiring protection', 'log', 60, true, 'global', 'system'),
('sys_pii_booking_ref', 'Booking Reference Logging', 'pii-global', 'system',
 '\b[A-Z0-9]{6}\b', 'low',
 'Booking reference detected - logged for audit trail (not blocked)', 'log', 10, true, 'global', 'system')

ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    tier = EXCLUDED.tier,
    pattern = EXCLUDED.pattern,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    action = EXCLUDED.action,
    priority = EXCLUDED.priority,
    enabled = EXCLUDED.enabled,
    created_by = EXCLUDED.created_by,
    updated_at = NOW();

-- =============================================================================
-- PII Detection - US Patterns (2 patterns)
-- Category: pii-us
-- =============================================================================

INSERT INTO static_policies (
    policy_id, name, category, tier, pattern, severity, description, action, priority, enabled, tenant_id, created_by
) VALUES
('sys_pii_ssn', 'SSN Detection', 'pii-us', 'system',
 '\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b', 'critical',
 'Social Security Number detected - automatic redaction required', 'block', 100, true, 'global', 'system'),
('sys_pii_bank_account', 'Bank Account Detection', 'pii-us', 'system',
 '\b[0-9]{9}[- ]?[0-9]{8,17}\b', 'critical',
 'Bank account information detected - automatic redaction required', 'block', 100, true, 'global', 'system')

ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    tier = EXCLUDED.tier,
    pattern = EXCLUDED.pattern,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    action = EXCLUDED.action,
    priority = EXCLUDED.priority,
    enabled = EXCLUDED.enabled,
    created_by = EXCLUDED.created_by,
    updated_at = NOW();

-- =============================================================================
-- PII Detection - EU Patterns (1 pattern)
-- Category: pii-eu
-- =============================================================================

INSERT INTO static_policies (
    policy_id, name, category, tier, pattern, severity, description, action, priority, enabled, tenant_id, created_by
) VALUES
('sys_pii_iban', 'IBAN Detection', 'pii-eu', 'system',
 '\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b', 'critical',
 'International Bank Account Number detected - automatic redaction required', 'block', 100, true, 'global', 'system')

ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    tier = EXCLUDED.tier,
    pattern = EXCLUDED.pattern,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    action = EXCLUDED.action,
    priority = EXCLUDED.priority,
    enabled = EXCLUDED.enabled,
    created_by = EXCLUDED.created_by,
    updated_at = NOW();

-- =============================================================================
-- PII Detection - India Patterns (2 patterns)
-- Category: pii-india
-- =============================================================================

INSERT INTO static_policies (
    policy_id, name, category, tier, pattern, severity, description, action, priority, enabled, tenant_id, created_by
) VALUES
('sys_pii_pan', 'Indian PAN Detection', 'pii-india', 'system',
 '\b[A-Z]{3}[PCHABGJLFT][A-Z][0-9]{4}[A-Z]\b|(?i)PAN[:\s]+\b[A-Z0-9]{10}\b', 'critical',
 'Indian Permanent Account Number (PAN) detected - automatic redaction required under SEBI guidelines', 'block', 100, true, 'global', 'system'),
('sys_pii_aadhaar', 'Indian Aadhaar Detection', 'pii-india', 'system',
 '\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b|(?i)aadhaar[:\s]+[2-9][0-9]{11}|(?i)UID[:\s]+[2-9][0-9]{11}', 'critical',
 'Indian Aadhaar number detected - automatic redaction required under DPDP Act 2023', 'block', 100, true, 'global', 'system')

ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    tier = EXCLUDED.tier,
    pattern = EXCLUDED.pattern,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    action = EXCLUDED.action,
    priority = EXCLUDED.priority,
    enabled = EXCLUDED.enabled,
    created_by = EXCLUDED.created_by,
    updated_at = NOW();

-- =============================================================================
-- PHASE 2: Dynamic System Policies (10 total)
-- =============================================================================

-- First, update any existing policies to be non-system (they'll be replaced)
UPDATE dynamic_policies SET tier = 'tenant' WHERE tier = 'system' OR tier IS NULL;

-- =============================================================================
-- Dynamic Risk Policies (2 policies)
-- Category: dynamic-risk
-- =============================================================================

INSERT INTO dynamic_policies (
    policy_id, name, description, policy_type, category, tier, conditions, actions, priority, enabled, tenant_id
) VALUES
('sys_dyn_high_risk_block', 'Block High-Risk Queries', 'Block queries with risk score above safety threshold',
 'risk_based', 'dynamic-risk', 'system',
 '[{"field": "risk_score", "operator": "greater_than", "value": 0.8}]',
 '[{"type": "block", "config": {"reason": "Query risk score exceeds safety threshold"}}]',
 1000, true, 'global'),
('sys_dyn_anomalous_access', 'Anomalous Access Detection', 'Detect and flag anomalous access patterns for review',
 'risk_based', 'dynamic-risk', 'system',
 '[{"field": "risk_score", "operator": "greater_than", "value": 0.6}, {"field": "user.access_pattern", "operator": "equals", "value": "anomalous"}]',
 '[{"type": "alert", "config": {"severity": "warning", "message": "Anomalous access pattern detected"}}]',
 900, true, 'global')

ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    policy_type = EXCLUDED.policy_type,
    category = EXCLUDED.category,
    tier = EXCLUDED.tier,
    conditions = EXCLUDED.conditions,
    actions = EXCLUDED.actions,
    priority = EXCLUDED.priority,
    enabled = EXCLUDED.enabled,
    updated_at = NOW();

-- =============================================================================
-- Dynamic Compliance Policies (3 policies)
-- Category: dynamic-compliance
-- =============================================================================

INSERT INTO dynamic_policies (
    policy_id, name, description, policy_type, category, tier, conditions, actions, priority, enabled, tenant_id
) VALUES
('sys_dyn_hipaa', 'HIPAA Compliance', 'Enforce HIPAA compliance for healthcare data access',
 'compliance', 'dynamic-compliance', 'system',
 '[{"field": "query", "operator": "contains_any", "value": ["patient", "diagnosis", "treatment", "medical_record", "prescription"]}]',
 '[{"type": "redact", "config": {"fields": ["patient_id", "ssn", "medical_record_number"]}}, {"type": "log", "config": {"compliance": "hipaa"}}]',
 950, true, 'global'),
('sys_dyn_gdpr', 'GDPR Compliance', 'Enforce GDPR compliance for EU personal data',
 'compliance', 'dynamic-compliance', 'system',
 '[{"field": "user.region", "operator": "in", "value": ["EU", "EEA", "UK"]}]',
 '[{"type": "redact", "config": {"fields": ["email", "phone", "address", "ip_address"]}}, {"type": "log", "config": {"compliance": "gdpr"}}]',
 950, true, 'global'),
('sys_dyn_financial', 'Financial Data Protection', 'Protect financial data with additional access controls',
 'compliance', 'dynamic-compliance', 'system',
 '[{"field": "query", "operator": "contains_any", "value": ["account_balance", "transaction", "credit_score", "salary"]}]',
 '[{"type": "redact", "config": {"fields": ["account_number", "credit_card", "ssn"]}}, {"type": "log", "config": {"compliance": "pci-dss"}}]',
 950, true, 'global')

ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    policy_type = EXCLUDED.policy_type,
    category = EXCLUDED.category,
    tier = EXCLUDED.tier,
    conditions = EXCLUDED.conditions,
    actions = EXCLUDED.actions,
    priority = EXCLUDED.priority,
    enabled = EXCLUDED.enabled,
    updated_at = NOW();

-- =============================================================================
-- Dynamic Security Policies (2 policies)
-- Category: dynamic-security
-- =============================================================================

INSERT INTO dynamic_policies (
    policy_id, name, description, policy_type, category, tier, conditions, actions, priority, enabled, tenant_id
) VALUES
('sys_dyn_tenant_isolation', 'Tenant Isolation', 'Ensure strict tenant data isolation in multi-tenant environment',
 'context_aware', 'dynamic-security', 'system',
 '[{"field": "query", "operator": "regex", "value": "tenant_id\\s*[!=<>]+"}]',
 '[{"type": "block", "config": {"reason": "Cross-tenant data access attempt blocked"}}]',
 1000, true, 'global'),
('sys_dyn_debug_restrict', 'Debug Mode Restriction', 'Restrict debug mode queries to development environments',
 'context_aware', 'dynamic-security', 'system',
 '[{"field": "query", "operator": "contains", "value": "debug"}, {"field": "environment", "operator": "not_equals", "value": "development"}]',
 '[{"type": "block", "config": {"reason": "Debug queries are only allowed in development environment"}}]',
 800, true, 'global')

ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    policy_type = EXCLUDED.policy_type,
    category = EXCLUDED.category,
    tier = EXCLUDED.tier,
    conditions = EXCLUDED.conditions,
    actions = EXCLUDED.actions,
    priority = EXCLUDED.priority,
    enabled = EXCLUDED.enabled,
    updated_at = NOW();

-- =============================================================================
-- Dynamic Cost Policies (2 policies)
-- Category: dynamic-cost
-- =============================================================================

INSERT INTO dynamic_policies (
    policy_id, name, description, policy_type, category, tier, conditions, actions, priority, enabled, tenant_id
) VALUES
('sys_dyn_expensive_query', 'Expensive Query Limit', 'Limit execution of resource-intensive queries',
 'cost', 'dynamic-cost', 'system',
 '[{"field": "cost_estimate", "operator": "greater_than", "value": 100}]',
 '[{"type": "alert", "config": {"severity": "warning", "message": "High-cost query detected"}}, {"type": "log", "config": {"metric": "query_cost"}}]',
 700, true, 'global'),
('sys_dyn_llm_cost', 'LLM Cost Optimization', 'Optimize LLM usage to control costs',
 'cost', 'dynamic-cost', 'system',
 '[{"field": "request_type", "operator": "equals", "value": "llm_chat"}, {"field": "user.monthly_llm_usage", "operator": "greater_than", "value": 1000}]',
 '[{"type": "modify_risk", "config": {"add": 0.2}}, {"type": "alert", "config": {"severity": "info", "message": "User approaching LLM usage limit"}}]',
 600, true, 'global')

ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    policy_type = EXCLUDED.policy_type,
    category = EXCLUDED.category,
    tier = EXCLUDED.tier,
    conditions = EXCLUDED.conditions,
    actions = EXCLUDED.actions,
    priority = EXCLUDED.priority,
    enabled = EXCLUDED.enabled,
    updated_at = NOW();

-- =============================================================================
-- Dynamic Access Policies (1 policy)
-- Category: dynamic-access
-- =============================================================================

INSERT INTO dynamic_policies (
    policy_id, name, description, policy_type, category, tier, conditions, actions, priority, enabled, tenant_id
) VALUES
('sys_dyn_sensitive_data', 'Sensitive Data Control', 'Redact sensitive data fields in responses',
 'context_aware', 'dynamic-access', 'system',
 '[{"field": "query", "operator": "contains_any", "value": ["salary", "ssn", "medical_record"]}]',
 '[{"type": "redact", "config": {"fields": ["salary", "ssn", "medical_record"]}}]',
 900, true, 'global')

ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    policy_type = EXCLUDED.policy_type,
    category = EXCLUDED.category,
    tier = EXCLUDED.tier,
    conditions = EXCLUDED.conditions,
    actions = EXCLUDED.actions,
    priority = EXCLUDED.priority,
    enabled = EXCLUDED.enabled,
    updated_at = NOW();

-- =============================================================================
-- Verification
-- =============================================================================

-- Verify counts
DO $$
DECLARE
    static_count INTEGER;
    dynamic_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO static_count FROM static_policies WHERE tier = 'system';
    SELECT COUNT(*) INTO dynamic_count FROM dynamic_policies WHERE tier = 'system';

    RAISE NOTICE 'System policies seeded: % static, % dynamic (total: %)',
        static_count, dynamic_count, static_count + dynamic_count;

    -- Verify expected counts
    IF static_count < 53 THEN
        RAISE WARNING 'Expected at least 53 static system policies, got %', static_count;
    END IF;

    IF dynamic_count < 10 THEN
        RAISE WARNING 'Expected at least 10 dynamic system policies, got %', dynamic_count;
    END IF;
END $$;

-- Migration complete
-- Total system policies: 63 (53 static + 10 dynamic)
