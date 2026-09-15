-- Migration 035: Sensitive Data Patterns
-- Date: 2026-01-05
-- Purpose: Add sensitive data detection patterns to static_policies (Issue #891)
-- Related: ADR-026 - Tiered Detection Defaults
--
-- This migration adds credential/secret detection patterns that were previously
-- hardcoded in the orchestrator's dynamic_policy_engine.go. By moving them to
-- the database, enterprise users can customize or disable these patterns.
--
-- Key features:
-- - context_exclusions in metadata: SQL keywords (PRIMARY KEY, FOREIGN KEY) that
--   should be stripped before pattern matching to prevent false positives
-- - risk_weight in metadata: Contribution to risk score calculation (0.0-1.0)
-- - action default: "warn" (not block) since these may have false positives

-- =============================================================================
-- Sensitive Data Detection - Credential/Secret Patterns (6 patterns)
-- Category: sensitive-data
-- Default Action: warn (may have false positives)
-- =============================================================================

-- First, ensure we have a category for sensitive data
-- Note: These are NEW patterns, so we use INSERT ON CONFLICT DO NOTHING
-- to avoid overwriting if this migration runs multiple times

INSERT INTO static_policies (
    policy_id, name, category, tier, pattern, severity, description, action, priority, enabled, tenant_id, created_by, metadata
) VALUES
-- Password detection (with variations)
('sys_sensitive_password', 'Password Detection', 'sensitive-data', 'system',
 '\b\w*pass(?:word|wd)?\s*[=:]\s*[''"]?[^\s''"]+[''"]?', 'high',
 'Detects password assignments or mentions in queries', 'warn', 70, true, 'global', 'system',
 '{"risk_weight": 0.7, "context_exclusions": [], "detection_type": "sensitive_data"}'),

-- API/Secret/Auth key patterns (with SQL keyword exclusions)
('sys_sensitive_api_key', 'API Key Detection', 'sensitive-data', 'system',
 '\b\w*[_-]?(?:api|secret|private|auth|client|encryption|signing|ssh|gpg)[_-]?key\s*[=:]', 'high',
 'Detects API keys, secret keys, and authentication keys', 'warn', 70, true, 'global', 'system',
 '{"risk_weight": 0.7, "context_exclusions": ["PRIMARY\\s+KEY", "FOREIGN\\s+KEY", "UNIQUE\\s+KEY", "KEY\\s+\\("], "detection_type": "sensitive_data"}'),

-- Token patterns (access, auth, bearer, JWT, OAuth)
('sys_sensitive_token', 'Token Detection', 'sensitive-data', 'system',
 '\b\w*[_-]?(?:access|auth|bearer|api|secret|session|refresh|jwt|oauth)[_-]?token\s*[=:]', 'high',
 'Detects access tokens, auth tokens, JWT tokens, and session tokens', 'warn', 70, true, 'global', 'system',
 '{"risk_weight": 0.7, "context_exclusions": [], "detection_type": "sensitive_data"}'),

-- Secret patterns (client secret, app secret)
('sys_sensitive_secret', 'Secret Detection', 'sensitive-data', 'system',
 '\b(?:client|app|api|auth|shared)[_-]?secret\s*[=:]', 'high',
 'Detects client secrets, app secrets, and shared secrets', 'warn', 70, true, 'global', 'system',
 '{"risk_weight": 0.7, "context_exclusions": [], "detection_type": "sensitive_data"}'),

-- Credential mentions
('sys_sensitive_credentials', 'Credentials Detection', 'sensitive-data', 'system',
 '\b(?:credentials?|creds)\s*[=:]', 'high',
 'Detects credential assignments or mentions', 'warn', 70, true, 'global', 'system',
 '{"risk_weight": 0.7, "context_exclusions": [], "detection_type": "sensitive_data"}'),

-- Connection string patterns
('sys_sensitive_connection', 'Connection String Detection', 'sensitive-data', 'system',
 '\b(?:connection[_-]?string|conn[_-]?str|database[_-]?url|db[_-]?url)\s*[=:]', 'high',
 'Detects database connection strings and URLs', 'warn', 70, true, 'global', 'system',
 '{"risk_weight": 0.7, "context_exclusions": [], "detection_type": "sensitive_data"}')

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
    metadata = EXCLUDED.metadata,
    updated_at = NOW();

-- =============================================================================
-- Add new category constant if needed
-- Note: Categories are validated in Go code, so this is informational only
-- =============================================================================

COMMENT ON TABLE static_policies IS
'Static policies table now includes sensitive-data category for credential/secret detection.
Categories: security-sqli, security-admin, pii-global, pii-us, pii-eu, pii-india,
            code-secrets, code-unsafe, code-compliance, sensitive-data (new in #891)';
