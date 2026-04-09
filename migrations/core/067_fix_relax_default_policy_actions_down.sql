-- Migration 067 (DOWN): Restore strict defaults with the correct discriminator.
-- Date: 2026-04-08
--
-- This down migration inverts the 067 up migration. It only reverses rows
-- that 067 actually changed: the up migration is guarded on
-- `action IN ('redact', 'block')` for the critical-PII set and on
-- `action = 'block'` for SQLi / sensitive / compliance.
--
-- Review fix: `sys_pii_email` and `sys_pii_phone` are NOT in the 067 up
-- migration's critical-PII policy_id list — they were never touched on the
-- way up. The previous version of this down migration unconditionally set
-- both to `warn`, which tightened their state on any database where they
-- had been left at their seeded value (`log`) — making the rollback
-- non-invertible. Email/phone are now deliberately excluded from the
-- rollback, matching the up migration's actual scope.

-- All PII including email/phone: warn → redact, BUT only for rows the
-- up migration actually changed.
--
-- The up migration's guard is `action IN ('redact', 'block')`. Any row
-- that was at 'log' (the seeded default for email/phone) is not touched
-- by the up migration. After up: if email/phone is at 'warn' on disk,
-- the ONLY path to that state is the up migration flipping it from
-- redact/block. So `WHERE action = 'warn'` is a safe exact-invert guard
-- — it will match exactly the rows up changed, and will NOT match the
-- seeded 'log' rows.
--
-- Previous version of this down migration unconditionally set email/phone
-- to 'warn', which tightened them relative to the seeded 'log' state and
-- broke invertibility. Fixed in v6.2.0 review follow-up.
UPDATE static_policies
SET action = 'redact',
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
  AND action = 'warn';

UPDATE static_policies
SET action = 'block',
    updated_at = NOW()
WHERE category IN ('security-sqli', 'sqli')
  AND (tenant_id IS NULL OR tenant_id = 'global')
  AND action = 'warn';

UPDATE static_policies
SET action = 'block',
    updated_at = NOW()
WHERE category IN ('sensitive-data', 'sensitive_data')
  AND (tenant_id IS NULL OR tenant_id = 'global')
  AND action = 'warn';

UPDATE static_policies
SET action = 'block',
    updated_at = NOW()
WHERE category IN (
    'compliance-hipaa', 'compliance-gdpr', 'compliance-pci',
    'compliance-rbi', 'compliance-mas-feat',
    'hipaa', 'gdpr', 'pci_dss', 'rbi', 'mas_feat'
) AND (tenant_id IS NULL OR tenant_id = 'global')
  AND action = 'log';

DO $$
BEGIN
    RAISE NOTICE 'Migration 067 (DOWN): restored strict default policy actions';
END $$;
