-- Migration 042: Singapore PII Detection Patterns
-- Created: 2026-01-24
-- Purpose: Add Singapore-specific PII detection patterns for MAS FEAT Community compliance
-- Related: Issue #1076 - MAS FEAT PII detection patterns (NRIC, FIN, UEN)
-- Parent EPIC: #1034 - MAS FEAT Community Edition
--
-- Singapore PII patterns enable detection of:
-- 1. NRIC (National Registration Identity Card) - S, T, F, G, M prefixes
-- 2. FIN (Foreign Identification Number) - F, G prefixes
-- 3. UEN (Unique Entity Number) - business registration numbers
-- 4. Singapore phone numbers (+65 format)
-- 5. Singapore postal codes (6 digits, 01-82 range)
--
-- Note: These are pattern-based detections only. Checksum validation is Enterprise-only.
-- Default action is 'redact' to balance security with usability.

-- =============================================================================
-- Singapore PII Detection Patterns (5 patterns)
-- Category: pii-singapore
-- Default Action: redact (non-blocking, preserves UX)
-- =============================================================================

INSERT INTO static_policies (
    policy_id, name, category, tier, pattern, severity, description, action, action_request, action_response, priority, enabled, tenant_id, created_by, metadata
) VALUES
-- NRIC Detection (National Registration Identity Card)
-- Format: [STFGM]XXXXXXX[A-Z]
-- S = Singapore Citizen born before 2000
-- T = Singapore Citizen born 2000 onwards
-- F = Foreigner issued before 2000
-- G = Foreigner issued 2000 onwards
-- M = Foreigner issued 2022 onwards
('sys_pii_singapore_nric', 'Singapore NRIC Detection', 'pii-singapore', 'system',
 '\b[STFGM]\d{7}[A-Z]\b', 'critical',
 'Singapore National Registration Identity Card detected - automatic redaction for MAS FEAT compliance',
 'redact', 'warn', 'redact', 100, true, 'global', 'system',
 '{"risk_weight": 0.9, "context_exclusions": [], "detection_type": "pii", "regulatory_framework": "MAS_FEAT", "data_category": "national_id"}'),

-- FIN Detection (Foreign Identification Number)
-- Format: [FG]XXXXXXX[A-Z]
-- Subset of NRIC but tracked separately for compliance reporting
('sys_pii_singapore_fin', 'Singapore FIN Detection', 'pii-singapore', 'system',
 '\b[FG]\d{7}[A-Z]\b', 'critical',
 'Singapore Foreign Identification Number detected - automatic redaction for MAS FEAT compliance',
 'redact', 'warn', 'redact', 100, true, 'global', 'system',
 '{"risk_weight": 0.9, "context_exclusions": [], "detection_type": "pii", "regulatory_framework": "MAS_FEAT", "data_category": "foreign_id"}'),

-- UEN Detection (Unique Entity Number)
-- Formats:
-- - Business (ROB): 8 digits + 1 letter (e.g., 53276128A)
-- - Local Company (ROC): 9 digits + 1 letter (e.g., 200312345A)
-- - Others: T/S + 2 digits + 2 letters + 4 digits + 1 letter (e.g., T08GA0001A)
('sys_pii_singapore_uen', 'Singapore UEN Detection', 'pii-singapore', 'system',
 '\b\d{8,9}[A-Z]\b|\b[TS]\d{2}[A-Z]{2}\d{4}[A-Z]\b', 'high',
 'Singapore Unique Entity Number detected - automatic redaction for MAS FEAT compliance',
 'redact', 'warn', 'redact', 90, true, 'global', 'system',
 '{"risk_weight": 0.7, "context_exclusions": [], "detection_type": "pii", "regulatory_framework": "MAS_FEAT", "data_category": "business_id"}'),

-- Singapore Phone Number Detection
-- Format: +65 followed by 8 digits starting with 6, 8, or 9
-- 6XXX XXXX = landline
-- 8XXX XXXX, 9XXX XXXX = mobile
('sys_pii_singapore_phone', 'Singapore Phone Detection', 'pii-singapore', 'system',
 '\+65\s?[689]\d{3}\s?\d{4}\b', 'medium',
 'Singapore phone number detected - redaction recommended for privacy',
 'redact', 'warn', 'redact', 70, true, 'global', 'system',
 '{"risk_weight": 0.5, "context_exclusions": [], "detection_type": "pii", "regulatory_framework": "MAS_FEAT", "data_category": "phone"}'),

-- Singapore Postal Code Detection
-- Format: 6 digits in range 01XXXX to 82XXXX
-- Lower severity as postal codes are less sensitive than IDs
('sys_pii_singapore_postal', 'Singapore Postal Code Detection', 'pii-singapore', 'system',
 '\b(?:0[1-9]|[1-7]\d|8[0-2])\d{4}\b', 'low',
 'Singapore postal code detected - may reveal location, logged for audit',
 'warn', 'log', 'log', 30, true, 'global', 'system',
 '{"risk_weight": 0.2, "context_exclusions": ["zip", "code", "ID", "order"], "detection_type": "pii", "regulatory_framework": "MAS_FEAT", "data_category": "location"}')

ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    tier = EXCLUDED.tier,
    pattern = EXCLUDED.pattern,
    severity = EXCLUDED.severity,
    description = EXCLUDED.description,
    action = EXCLUDED.action,
    action_request = EXCLUDED.action_request,
    action_response = EXCLUDED.action_response,
    priority = EXCLUDED.priority,
    enabled = EXCLUDED.enabled,
    created_by = EXCLUDED.created_by,
    metadata = EXCLUDED.metadata,
    updated_at = NOW();

-- =============================================================================
-- Update table comment to reflect new category
-- =============================================================================

COMMENT ON TABLE static_policies IS
'Static policies table for pattern-based detection.
Categories: security-sqli, security-admin, pii-global, pii-us, pii-eu, pii-india,
            pii-singapore (new in #1076), code-secrets, code-unsafe, code-compliance, sensitive-data';
