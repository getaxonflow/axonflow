-- Migration 066 (DOWN): Restore Strict Default Policy Actions
-- Date: 2026-04-09
-- Purpose: Reverse migration 066 — restore the v6.1.0 default actions.

-- PII: warn → redact (matches migration 036 state)
UPDATE static_policies
SET action = 'redact',
    description = REPLACE(description, 'flagged (warn)', 'flagged for automatic redaction'),
    updated_at = NOW()
WHERE policy_id IN (
    'sys_pii_credit_card',
    'sys_pii_ssn',
    'sys_pii_bank_account',
    'sys_pii_iban',
    'sys_pii_pan',
    'sys_pii_aadhaar',
    'sys_pii_passport'
) AND tenant_id IS NULL
  AND action = 'warn';

-- Email + phone PII didn't have a redact default in 036; restore to warn
-- (no-op — they already are warn).

-- SQLi: warn → block
UPDATE static_policies
SET action = 'block',
    updated_at = NOW()
WHERE category IN ('security-sqli', 'sqli')
  AND tenant_id IS NULL
  AND action = 'warn';

-- Sensitive data: warn → block
UPDATE static_policies
SET action = 'block',
    updated_at = NOW()
WHERE category IN ('sensitive-data', 'sensitive_data')
  AND tenant_id IS NULL
  AND action = 'warn';

-- Compliance: log → block (most aggressive prior posture)
UPDATE static_policies
SET action = 'block',
    updated_at = NOW()
WHERE category IN (
    'compliance-hipaa', 'compliance-gdpr', 'compliance-pci',
    'compliance-rbi', 'compliance-mas-feat',
    'hipaa', 'gdpr', 'pci_dss', 'rbi', 'mas_feat'
) AND tenant_id IS NULL
  AND action = 'log';

DO $$
BEGIN
    RAISE NOTICE 'Migration 066 (DOWN): Restored strict default policy actions';
END $$;
