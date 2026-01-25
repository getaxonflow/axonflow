-- Migration 042 DOWN: Remove Singapore PII Detection Patterns
-- Related: Issue #1076 - MAS FEAT PII detection patterns (NRIC, FIN, UEN)

-- Remove Singapore PII patterns
DELETE FROM static_policies WHERE policy_id IN (
    'sys_pii_singapore_nric',
    'sys_pii_singapore_fin',
    'sys_pii_singapore_uen',
    'sys_pii_singapore_phone',
    'sys_pii_singapore_postal'
);

-- Revert table comment
COMMENT ON TABLE static_policies IS
'Static policies table for pattern-based detection.
Categories: security-sqli, security-admin, pii-global, pii-us, pii-eu, pii-india,
            code-secrets, code-unsafe, code-compliance, sensitive-data';
