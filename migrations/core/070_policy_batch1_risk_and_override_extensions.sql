-- Migration 070: Plugin Batch 1 — risk_level + allow_override on policies,
-- extended columns on policy_overrides.
--
-- Ships with platform v7.1.0.
--
-- Adds the schema changes that ADR-044 (session override semantics) and
-- ADR-043 (explainability data contract) need on top of migration 030's
-- policy_overrides table and migration 010's policy tables.
--
-- Backwards-compatible: every ALTER is IF NOT EXISTS or uses a column with
-- a default value, so existing rows get sensible values.

BEGIN;

-- =============================================================================
-- 1) static_policies: risk_level + allow_override
-- =============================================================================

ALTER TABLE IF EXISTS static_policies
    ADD COLUMN IF NOT EXISTS risk_level TEXT NOT NULL DEFAULT 'medium'
        CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    ADD COLUMN IF NOT EXISTS allow_override BOOLEAN NOT NULL DEFAULT TRUE;

-- Seed sensible risk defaults based on category. Dangerous-command and
-- privilege-escalation categories become critical (override forbidden by
-- contract). SQLi, prompt injection, and secret leaks become high.
UPDATE static_policies
SET risk_level = 'critical', allow_override = FALSE
WHERE category IN (
    'dangerous-command',
    'rce',
    'privilege-escalation',
    'system-destruction'
)
  AND risk_level = 'medium';

UPDATE static_policies
SET risk_level = 'high'
WHERE category IN (
    'security-sqli',
    'prompt-injection',
    'secret-leak'
)
  AND risk_level = 'medium';

-- =============================================================================
-- 2) dynamic_policies: risk_level + allow_override
-- =============================================================================

ALTER TABLE IF EXISTS dynamic_policies
    ADD COLUMN IF NOT EXISTS risk_level TEXT NOT NULL DEFAULT 'medium'
        CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    ADD COLUMN IF NOT EXISTS allow_override BOOLEAN NOT NULL DEFAULT TRUE;

-- =============================================================================
-- 3) policy_overrides: ADR-044 extensions
-- =============================================================================

-- Drop the legacy action_override CHECK so we can widen the allowed values
-- to include 'allow' (session-override use case). Re-add the constraint with
-- the full set used by Plugin Batch 1 + the legacy values that migration 030
-- installed.
ALTER TABLE policy_overrides
    DROP CONSTRAINT IF EXISTS policy_overrides_action_override_check;

ALTER TABLE policy_overrides
    ADD CONSTRAINT policy_overrides_action_override_check
    CHECK (action_override IN ('block', 'warn', 'log', 'allow', 'deny', 'require_approval', 'log_only'));

-- New columns for Plugin Batch 1 scope rules and revocation audit.
ALTER TABLE policy_overrides
    ADD COLUMN IF NOT EXISTS tool_signature TEXT,
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS revoked_by VARCHAR(255);

-- Indexes used by FindActiveOverride and list handlers.
CREATE INDEX IF NOT EXISTS idx_policy_overrides_lookup_v2
    ON policy_overrides(tenant_id, created_by, policy_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_policy_overrides_expiry_v2
    ON policy_overrides(expires_at)
    WHERE revoked_at IS NULL AND expires_at IS NOT NULL;

-- =============================================================================
-- 4) Contract enforcement: critical risk_level => allow_override = FALSE
-- =============================================================================
-- Enforced at the DB level so a policy document or API caller can't
-- accidentally set allow_override=TRUE on a critical-risk policy.

CREATE OR REPLACE FUNCTION enforce_critical_no_override()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.risk_level = 'critical' AND NEW.allow_override = TRUE THEN
        NEW.allow_override := FALSE;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_static_policies_critical_no_override ON static_policies;
CREATE TRIGGER trg_static_policies_critical_no_override
    BEFORE INSERT OR UPDATE ON static_policies
    FOR EACH ROW
    EXECUTE FUNCTION enforce_critical_no_override();

DROP TRIGGER IF EXISTS trg_dynamic_policies_critical_no_override ON dynamic_policies;
CREATE TRIGGER trg_dynamic_policies_critical_no_override
    BEFORE INSERT OR UPDATE ON dynamic_policies
    FOR EACH ROW
    EXECUTE FUNCTION enforce_critical_no_override();

-- =============================================================================
-- 5) Audit index for explain-on-demand
-- =============================================================================
-- explain endpoint looks up by policy_details->>'decision_id'. A functional
-- index over that JSONB field keeps the lookup sub-ms even on large audit
-- tables.

CREATE INDEX IF NOT EXISTS idx_audit_decision_id
    ON audit_logs ((policy_details->>'decision_id'))
    WHERE policy_details IS NOT NULL;

COMMIT;
