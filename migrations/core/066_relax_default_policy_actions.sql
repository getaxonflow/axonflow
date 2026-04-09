-- Migration 066: Relax Default Policy Actions for v6.2.0 Governance UX
-- Date: 2026-04-09
-- Purpose: Reverse migration 036 and broaden it: relax default actions on
--          system-default policies to match the new "default" profile
--          (PII=warn, SQLi=warn, sensitive=warn, dangerous=block).
-- Related: ADR-036 (Governance Profiles), Issue #1545
--
-- Philosophy (v6.2.0+):
--   - Block ONLY unambiguously dangerous patterns by default
--     (reverse shells, rm -rf, SSRF to metadata, /etc/shadow, credentials)
--   - Warn on PII / SQLi / sensitive data — surface the detection without
--     silent data mutation (redact) or hard-blocking legitimate flows
--   - Compliance categories (HIPAA / GDPR / PCI / RBI / MAS) → log only;
--     opt in with AXONFLOW_PROFILE=compliance
--
-- Rationale: Silent redaction breaks debugging mid-session and teaches
-- evaluators that AxonFlow is "broken". False positives are worse than
-- under-policing because they teach people to bypass the system. Operators
-- can restore the v6.1.0 behavior with AXONFLOW_PROFILE=strict.
--
-- Scope: Only system-default policies (tenant_id IS NULL). User-created
-- and tenant-owned policies are untouched.

-- =============================================================================
-- PII policies: redact → warn
-- =============================================================================
-- Migration 036 set these to 'redact'. We're relaxing further to 'warn' so
-- the data flows through unchanged but the detection still surfaces.

UPDATE static_policies
SET action = 'warn',
    description = REPLACE(description, 'flagged for automatic redaction', 'flagged (warn)'),
    updated_at = NOW()
WHERE policy_id IN (
    'sys_pii_credit_card',
    'sys_pii_ssn',
    'sys_pii_bank_account',
    'sys_pii_iban',
    'sys_pii_pan',
    'sys_pii_aadhaar',
    'sys_pii_passport',
    'sys_pii_email',
    'sys_pii_phone'
) AND tenant_id IS NULL
  AND action IN ('redact', 'block');

-- =============================================================================
-- SQLi policies: block → warn
-- =============================================================================

UPDATE static_policies
SET action = 'warn',
    updated_at = NOW()
WHERE category IN ('security-sqli', 'sqli')
  AND tenant_id IS NULL
  AND action = 'block';

-- =============================================================================
-- Sensitive data policies: block → warn
-- =============================================================================

UPDATE static_policies
SET action = 'warn',
    updated_at = NOW()
WHERE category IN ('sensitive-data', 'sensitive_data')
  AND tenant_id IS NULL
  AND action = 'block';

-- =============================================================================
-- Compliance categories: drop to log
-- =============================================================================
-- HIPAA / GDPR / PCI / RBI / MAS detection is logged for audit but does
-- not block by default. Operators wanting hard enforcement opt in via
-- AXONFLOW_PROFILE=compliance.

UPDATE static_policies
SET action = 'log',
    updated_at = NOW()
WHERE category IN (
    'compliance-hipaa', 'compliance-gdpr', 'compliance-pci',
    'compliance-rbi', 'compliance-mas-feat',
    'hipaa', 'gdpr', 'pci_dss', 'rbi', 'mas_feat'
) AND tenant_id IS NULL
  AND action IN ('block', 'redact', 'warn');

-- =============================================================================
-- Dangerous command policies: stay block
-- =============================================================================
-- Migration 059 added these. They MUST continue to block by default
-- (reverse shells, rm -rf, SSRF to metadata, /etc/shadow, credentials).
-- This block is intentionally a no-op for clarity — listed so a future
-- maintainer reading this migration sees the explicit decision.

-- (no UPDATE — sys_dangerous_* policies stay 'block')

-- =============================================================================
-- Audit
-- =============================================================================

DO $$
DECLARE
    pii_count INTEGER;
    sqli_count INTEGER;
    sensitive_count INTEGER;
    compliance_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO pii_count FROM static_policies
        WHERE policy_id LIKE 'sys_pii_%' AND tenant_id IS NULL AND action = 'warn';
    SELECT COUNT(*) INTO sqli_count FROM static_policies
        WHERE category IN ('security-sqli', 'sqli') AND tenant_id IS NULL AND action = 'warn';
    SELECT COUNT(*) INTO sensitive_count FROM static_policies
        WHERE category IN ('sensitive-data', 'sensitive_data') AND tenant_id IS NULL AND action = 'warn';
    SELECT COUNT(*) INTO compliance_count FROM static_policies
        WHERE category IN ('compliance-hipaa', 'compliance-gdpr', 'compliance-pci',
                           'compliance-rbi', 'compliance-mas-feat', 'hipaa', 'gdpr',
                           'pci_dss', 'rbi', 'mas_feat')
          AND tenant_id IS NULL AND action = 'log';

    RAISE NOTICE 'Migration 066: Governance UX defaults relaxed';
    RAISE NOTICE '  - PII policies (warn):        %', pii_count;
    RAISE NOTICE '  - SQLi policies (warn):       %', sqli_count;
    RAISE NOTICE '  - Sensitive policies (warn):  %', sensitive_count;
    RAISE NOTICE '  - Compliance policies (log):  %', compliance_count;
    RAISE NOTICE '  - Dangerous commands stay block';
    RAISE NOTICE '  - To restore v6.1.0 behavior: AXONFLOW_PROFILE=strict';
END $$;
