-- Migration 036: Update Policy Action Defaults
-- Date: 2026-01-05
-- Purpose: Change default actions for tiered detection (Issue #891)
-- Related: ADR-026 - Tiered Detection Defaults
--
-- Philosophy: Block high-confidence threats, warn on heuristics, redact PII.
--
-- Changes:
-- - PII detection (critical): block → redact (non-blocking, preserves UX)
-- - High risk score policy: block → warn (composite score needs tuning)
--
-- Note: SQL injection and dangerous queries remain as block (high confidence)

-- =============================================================================
-- Update PII Policies: block → redact
-- =============================================================================

-- Update critical PII patterns to use redact instead of block
-- This is the key UX improvement: PII is still detected and handled,
-- but requests are not blocked, allowing the conversation to continue

UPDATE static_policies
SET action = 'redact',
    description = REPLACE(description, 'automatic redaction required', 'flagged for automatic redaction'),
    updated_at = NOW()
WHERE policy_id IN (
    'sys_pii_credit_card',
    'sys_pii_ssn',
    'sys_pii_bank_account',
    'sys_pii_iban',
    'sys_pii_pan',
    'sys_pii_aadhaar',
    'sys_pii_passport'
) AND action = 'block';

-- =============================================================================
-- Update High Risk Policy: block → warn
-- =============================================================================

-- The high risk score policy uses a composite score that may need tuning
-- per environment. Default to warn to reduce friction during evaluation.

UPDATE dynamic_policies
SET actions = '[{"type": "warn", "config": {"reason": "Query risk score exceeds safety threshold"}}]'::jsonb,
    description = 'Warn on queries with risk score above safety threshold (previously blocked)',
    updated_at = NOW()
WHERE policy_id = 'sys_dyn_high_risk_block';

-- =============================================================================
-- Log the changes for audit trail
-- =============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Migration 036: Updated policy defaults for tiered detection (Issue #891)';
    RAISE NOTICE '  - PII policies (7): block → redact';
    RAISE NOTICE '  - High risk policy: block → warn';
END $$;
