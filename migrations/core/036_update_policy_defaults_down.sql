-- Migration 036 DOWN: Revert Policy Action Defaults
-- Date: 2026-01-05
-- Purpose: Restore original block actions (Issue #891)

-- Restore PII policies to block
UPDATE static_policies
SET action = 'block',
    description = REPLACE(description, 'flagged for automatic redaction', 'automatic redaction required'),
    updated_at = NOW()
WHERE policy_id IN (
    'sys_pii_credit_card',
    'sys_pii_ssn',
    'sys_pii_bank_account',
    'sys_pii_iban',
    'sys_pii_pan',
    'sys_pii_aadhaar',
    'sys_pii_passport'
);

-- Restore high risk policy to block
UPDATE dynamic_policies
SET actions = '[{"type": "block", "config": {"reason": "Query risk score exceeds safety threshold"}}]'::jsonb,
    description = 'Block queries with risk score above safety threshold',
    updated_at = NOW()
WHERE policy_id = 'sys_dyn_high_risk_block';
