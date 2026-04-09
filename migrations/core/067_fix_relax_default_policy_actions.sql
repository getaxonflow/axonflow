-- Migration 067: FIX migration 066 — tenant_id discriminator bug
-- Date: 2026-04-08 (fix for the same-day v6.2.0 release)
-- Purpose: Migration 066 used `WHERE tenant_id IS NULL` to target
--          system-default policies. But static_policies.tenant_id has
--          DEFAULT 'global' (per migration 010), so system-default rows
--          are stored with tenant_id = 'global', never NULL. Migration
--          066 matched ZERO rows and was a silent no-op.
--
--          This migration redoes the 066 UPDATEs with the correct
--          discriminator: tenant_id IS NULL OR tenant_id = 'global'
--          (the dual-discriminator convention used by the runtime Go
--          policy loader).
--
-- Safety:  Idempotent — re-running it on already-relaxed rows is a no-op
--          because of the action IN (...) filters.

-- =============================================================================
-- PII policies: redact/block → warn
-- =============================================================================

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
) AND (tenant_id IS NULL OR tenant_id = 'global')
  AND action IN ('redact', 'block');

-- =============================================================================
-- SQLi policies: block → warn
-- =============================================================================

UPDATE static_policies
SET action = 'warn',
    updated_at = NOW()
WHERE category IN ('security-sqli', 'sqli')
  AND (tenant_id IS NULL OR tenant_id = 'global')
  AND action = 'block';

-- =============================================================================
-- Sensitive data policies: block → warn
-- =============================================================================

UPDATE static_policies
SET action = 'warn',
    updated_at = NOW()
WHERE category IN ('sensitive-data', 'sensitive_data')
  AND (tenant_id IS NULL OR tenant_id = 'global')
  AND action = 'block';

-- =============================================================================
-- Compliance categories: drop to log
-- =============================================================================

UPDATE static_policies
SET action = 'log',
    updated_at = NOW()
WHERE category IN (
    'compliance-hipaa', 'compliance-gdpr', 'compliance-pci',
    'compliance-rbi', 'compliance-mas-feat',
    'hipaa', 'gdpr', 'pci_dss', 'rbi', 'mas_feat'
) AND (tenant_id IS NULL OR tenant_id = 'global')
  AND action IN ('block', 'redact', 'warn');

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
        WHERE policy_id LIKE 'sys_pii_%'
          AND (tenant_id IS NULL OR tenant_id = 'global')
          AND action = 'warn';
    SELECT COUNT(*) INTO sqli_count FROM static_policies
        WHERE category IN ('security-sqli', 'sqli')
          AND (tenant_id IS NULL OR tenant_id = 'global')
          AND action = 'warn';
    SELECT COUNT(*) INTO sensitive_count FROM static_policies
        WHERE category IN ('sensitive-data', 'sensitive_data')
          AND (tenant_id IS NULL OR tenant_id = 'global')
          AND action = 'warn';
    SELECT COUNT(*) INTO compliance_count FROM static_policies
        WHERE category IN ('compliance-hipaa', 'compliance-gdpr', 'compliance-pci',
                           'compliance-rbi', 'compliance-mas-feat', 'hipaa', 'gdpr',
                           'pci_dss', 'rbi', 'mas_feat')
          AND (tenant_id IS NULL OR tenant_id = 'global')
          AND action = 'log';

    RAISE NOTICE 'Migration 067: fixed 066 tenant_id discriminator bug';
    RAISE NOTICE '  - PII policies (warn):        %', pii_count;
    RAISE NOTICE '  - SQLi policies (warn):       %', sqli_count;
    RAISE NOTICE '  - Sensitive policies (warn):  %', sensitive_count;
    RAISE NOTICE '  - Compliance policies (log):  %', compliance_count;
END $$;
